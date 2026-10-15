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
    private var lastHeartbeat = DispatchTime.now()
    private let lifetime: TimeInterval
    private var lossHandler: (() -> Void)?
    private let stateLock = NSLock()

    convenience init(directory: URL) throws {
        try self.init(path: directory.appendingPathComponent(".storage-write.lock"), lifetime: 15)
    }

    init(path url: URL, lifetime: TimeInterval) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        path = url.path
        self.lifetime = lifetime
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
        return !heartbeatFailed && withinLease && ownsDirectory
    }

    private var ownsDirectory: Bool {
        var info = stat()
        return lstat(path, &info) == 0 && info.st_ino == inode && info.st_dev == device
    }

    private var withinLease: Bool {
        Double(DispatchTime.now().uptimeNanoseconds - lastHeartbeat.uptimeNanoseconds) / 1_000_000_000 < lifetime
    }

    func onLost(_ handler: @escaping () -> Void) {
        stateLock.lock()
        lossHandler = handler
        let lost = heartbeatFailed || !withinLease || !ownsDirectory
        stateLock.unlock()
        if lost { handler() }
    }

    private func heartbeat() {
        stateLock.lock()
        guard !heartbeatFailed && withinLease && ownsDirectory else {
            heartbeatFailed = true
            let handler = lossHandler
            stateLock.unlock()
            handler?()
            return
        }
        defer { stateLock.unlock() }
        do {
            try FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: path)
            lastHeartbeat = .now()
        } catch {
            heartbeatFailed = true
        }
    }

    func release() {
        stateLock.lock()
        lossHandler = nil
        stateLock.unlock()
        timer.cancel()
        queue.sync {}
        // Preserve a replacement owner's lock. Never steal busy or stale CLI locks;
        // defer the write when ownership is uncertain.
        if ownsDirectory { _ = rmdir(path) }
    }
}

/// Claude Code holds both locks across read, refresh and persistence. The legacy
/// lock uses the real config path, including for symlinked profile directories.
final class ClaudeRefreshLock: @unchecked Sendable {
    private let current: ClaudeStorageLock
    private let legacy: ClaudeStorageLock

    init(directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        current = try ClaudeStorageLock(path: directory.appendingPathComponent(".oauth_refresh.lock"), lifetime: 60)
        do {
            let path = directory.resolvingSymlinksInPath().path + ".lock"
            legacy = try ClaudeStorageLock(path: URL(fileURLWithPath: path), lifetime: 60)
        } catch {
            current.release()
            throw error
        }
    }

    var isHeld: Bool { current.isHeld && legacy.isHeld }

    func onLost(_ handler: @escaping () -> Void) {
        current.onLost(handler)
        legacy.onLost(handler)
    }

    func release() {
        legacy.release()
        current.release()
    }
}
