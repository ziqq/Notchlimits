import AppKit
import CryptoKit
import Foundation

/// Обновление в один клик: качаем .zip релиза, сверяем SHA-256, распаковываем,
/// снимаем карантин и подменяем бандл, затем перезапускаемся. Заменить папку
/// запущенного приложения на лету нельзя, поэтому саму подмену делает крошечный
/// скрипт: он ждёт выхода приложения, ставит новый бандл на место старого и
/// снова запускает. При провале — откат к старому бандлу.
enum UpdateInstaller {

    enum Failure: LocalizedError {
        case noAsset, download, checksumMissing, checksumMismatch, unpack, notFound, notWritable

        var errorDescription: String? {
            switch self {
            case .noAsset:          return L.t("update.err.noAsset")
            case .download:         return L.t("update.err.download")
            case .checksumMissing:  return L.t("update.err.checksum")
            case .checksumMismatch: return L.t("update.err.checksum")
            case .unpack:           return L.t("update.err.unpack")
            case .notFound:         return L.t("update.err.unpack")
            case .notWritable:      return L.t("update.err.notWritable")
            }
        }
    }

    /// Есть ли право заменить бандл на месте (родительская папка на запись).
    static func canInstallInPlace() -> Bool {
        let parent = Bundle.main.bundleURL.deletingLastPathComponent()
        return FileManager.default.isWritableFile(atPath: parent.path)
    }

    /// Скачать, проверить, распаковать и запустить подмену. Приложение должно
    /// завершиться сразу после — дальше работает скрипт.
    static func install(_ release: UpdateCheck.Release) async throws {
        guard let zipURL = release.downloadURL, isHTTPS(zipURL) else { throw Failure.noAsset }
        // Контрольная сумма обязательна: ставить бинарь без проверки нельзя.
        guard let checksumURL = release.checksumURL, isHTTPS(checksumURL) else {
            throw Failure.checksumMissing
        }
        guard canInstallInPlace() else { throw Failure.notWritable }

        let fileManager = FileManager.default
        let work = fileManager.temporaryDirectory
            .appendingPathComponent("NotchLimitsUpdate-\(UUID().uuidString)")
        try fileManager.createDirectory(at: work, withIntermediateDirectories: true)

        // 1. Скачиваем архив.
        let (tempZip, response) = try await URLSession.shared.download(from: zipURL)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw Failure.download }
        let zip = work.appendingPathComponent(zipURL.lastPathComponent)
        try fileManager.moveItem(at: tempZip, to: zip)

        // 2. Сверяем SHA-256 — ставим только то, что совпало с суммой из релиза.
        let (sumsData, sumsResponse) = try await URLSession.shared.data(from: checksumURL)
        guard (sumsResponse as? HTTPURLResponse)?.statusCode == 200 else { throw Failure.download }
        let sums = String(decoding: sumsData, as: UTF8.self)
        guard let expected = UpdateCheck.expectedSum(from: sums, zipName: zipURL.lastPathComponent)
        else { throw Failure.checksumMissing }
        guard sha256(of: zip) == expected else { throw Failure.checksumMismatch }

        // 3. Распаковываем (ditto сохраняет подпись и атрибуты).
        let unpacked = work.appendingPathComponent("unpacked")
        guard shell("/usr/bin/ditto", ["-x", "-k", zip.path, unpacked.path]) else { throw Failure.unpack }
        guard let newApp = firstApp(in: unpacked) else { throw Failure.notFound }

        // 4. Снимаем карантин, иначе Gatekeeper не даст запустить ad-hoc сборку.
        _ = shell("/usr/bin/xattr", ["-dr", "com.apple.quarantine", newApp.path])

        // 5. Пишем скрипт подмены и запускаем его отдельным процессом.
        let scriptURL = work.appendingPathComponent("swap.sh")
        let script = swapScript(pid: ProcessInfo.processInfo.processIdentifier,
                                old: Bundle.main.bundleURL, new: newApp)
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = [scriptURL.path]
        try task.run()   // переживёт наш выход и доделает подмену
    }

    // MARK: - Детали

    private static func isHTTPS(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https"
    }

    private static func sha256(of file: URL) -> String {
        guard let data = try? Data(contentsOf: file) else { return "" }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func firstApp(in directory: URL) -> URL? {
        let entries = (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil)) ?? []
        return entries.first { $0.pathExtension == "app" }
    }

    @discardableResult
    private static func shell(_ launchPath: String, _ arguments: [String]) -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: launchPath)
        task.arguments = arguments
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }

    /// Скрипт подмены. Пути в одинарных кавычках — так безопасно и с пробелами.
    private static func swapScript(pid: Int32, old: URL, new: URL) -> String {
        let oldPath = shellQuote(old.path)
        let newPath = shellQuote(new.path)
        return """
        #!/bin/bash
        # Ждём выхода приложения (\(pid)), затем ставим новый бандл на место.
        while /bin/kill -0 \(pid) 2>/dev/null; do sleep 0.2; done
        sleep 0.3
        OLD=\(oldPath)
        NEW=\(newPath)
        BACKUP="${OLD}.backup"
        /bin/rm -rf "$BACKUP"
        if /bin/mv "$OLD" "$BACKUP"; then
          if /usr/bin/ditto "$NEW" "$OLD"; then
            /usr/bin/xattr -dr com.apple.quarantine "$OLD" 2>/dev/null
            /bin/rm -rf "$BACKUP"
          else
            /bin/rm -rf "$OLD"; /bin/mv "$BACKUP" "$OLD"   # откат
          fi
        fi
        /usr/bin/open "$OLD"
        """
    }

    private static func shellQuote(_ path: String) -> String {
        "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
