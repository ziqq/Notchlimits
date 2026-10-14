import Darwin
import Foundation

/// Coordinates with Claude Code's secureStorage.mutate: mkdir `.storage-write.lock`
/// in the credentials directory and keep its mtime current while holding it.
final class ClaudeStorageLock: @unchecked Sendable {
    enum Failure: Error { case busy, lost }

    private let path: String
    private let inode: ino_t
    private let device: dev_t
    private let queue = DispatchQueue(label: "dev.ustinoff.notchlimits.claude-storage-lock")
    private let timer: DispatchSourceTimer
    private var heartbeatFailed = false
    private let stateLock = NSLock()

    init(directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        path = directory.appendingPathComponent(".storage-write.lock").path
        guard mkdir(path, 0o700) == 0 else { throw Failure.busy }
        var info = stat()
        guard lstat(path, &info) == 0 else {
            _ = rmdir(path)
            throw Failure.lost
        }
        inode = info.st_ino
        device = info.st_dev
        timer = DispatchSource.makeTimerSource(queue: queue)
        // CLI considers a lock stale after 15 seconds. Keychain can wait longer
        // for user authorization, so keep the heartbeat on a separate queue.
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in self?.heartbeat() }
        timer.resume()
    }

    var isHeld: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return !heartbeatFailed && ownsDirectory
    }

    private var ownsDirectory: Bool {
        var info = stat()
        return lstat(path, &info) == 0 && info.st_ino == inode && info.st_dev == device
    }

    private func heartbeat() {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard ownsDirectory else { heartbeatFailed = true; return }
        do {
            try FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: path)
        } catch {
            heartbeatFailed = true
        }
    }

    func release() {
        timer.cancel()
        queue.sync {}
        // Preserve a replacement owner's lock. Never steal busy or stale CLI locks;
        // defer the write when ownership is uncertain.
        if ownsDirectory { _ = rmdir(path) }
    }
}
