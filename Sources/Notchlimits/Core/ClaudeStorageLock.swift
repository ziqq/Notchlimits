import Darwin
import Foundation

/// Coordinates with Claude Code's secureStorage.mutate: mkdir `.storage-write.lock`
/// in the credentials directory and keep its mtime current while holding it.
final class ClaudeStorageLock: @unchecked Sendable {
    enum Failure: Error { case busy, lost }

    private let path: String
    private var identity: Identity
    private let queue = DispatchQueue(label: "dev.ustinoff.notchlimits.claude-storage-lock")
    private let timer: DispatchSourceTimer
    private let ownerFD: Int32
    private let directoryFD: Int32
    private var released = false
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
        // This sidecar stays empty of credentials. flock proves whether a
        // Notchlimits owner is still alive, even after a crash or PID reuse.
        let fd = open(path + ".notchlimits-owner", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.busy }
        var keepFD = false
        defer { if !keepFD { _ = close(fd) } }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw Failure.busy }
        if mkdir(path, 0o700) != 0 {
            guard errno == EEXIST, Self.recoverAbandoned(path: path, ownerFD: fd),
                  mkdir(path, 0o700) == 0 else { throw Failure.busy }
        }
        var info = stat()
        guard lstat(path, &info) == 0 else {
            _ = rmdir(path)
            throw Failure.lost
        }
        let identity = Identity(info)
        let directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else {
            if Identity.at(path) == identity { _ = rmdir(path) }
            throw Failure.lost
        }
        defer { if !keepFD { _ = close(directory) } }
        var opened = stat()
        guard fstat(directory, &opened) == 0, Identity(opened) == identity else { throw Failure.lost }
        do {
            try Self.store(identity, in: fd)
        } catch {
            if Identity.at(path) == identity { _ = rmdir(path) }
            throw error
        }
        ownerFD = fd
        directoryFD = directory
        keepFD = true
        self.identity = identity
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
        return !released && !heartbeatFailed && withinLease && ownsDirectory
    }

    private var ownsDirectory: Bool {
        guard let current = Identity.at(path) else { return false }
        // Keeping the directory descriptor open prevents inode reuse while held.
        // macOS can move birthtime backwards when a test or clock adjustment
        // sets mtime before creation, so birthtime is only a recovery discriminator.
        return current.inode == identity.inode && current.device == identity.device
    }

    private var withinLease: Bool {
        Double(DispatchTime.now().uptimeNanoseconds - lastHeartbeat.uptimeNanoseconds) / 1_000_000_000 < lifetime
    }

    func onLost(_ handler: @escaping () -> Void) {
        stateLock.lock()
        lossHandler = handler
        let lost = released || heartbeatFailed || !withinLease || !ownsDirectory
        stateLock.unlock()
        if lost { handler() }
    }

    private func heartbeat() {
        stateLock.lock()
        guard !released && !heartbeatFailed && withinLease && ownsDirectory else {
            heartbeatFailed = true
            let handler = lossHandler
            stateLock.unlock()
            handler?()
            return
        }
        defer { stateLock.unlock() }
        do {
            try FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: path)
            var info = stat()
            guard fstat(directoryFD, &info) == 0, ownsDirectory else { throw Failure.lost }
            let current = Identity(info)
            if current != identity {
                try Self.store(current, in: ownerFD)
                identity = current
            }
            lastHeartbeat = .now()
        } catch {
            heartbeatFailed = true
        }
    }

    func release() {
        stateLock.lock()
        guard !released else { stateLock.unlock(); return }
        released = true
        lossHandler = nil
        stateLock.unlock()
        timer.cancel()
        queue.sync {}
        // Preserve a replacement owner's lock. Never steal busy or stale CLI locks;
        // defer the write when ownership is uncertain.
        if ownsDirectory && rmdir(path) == 0 { _ = ftruncate(ownerFD, 0) }
        _ = close(directoryFD)
        _ = close(ownerFD)
    }

    deinit {
        timer.cancel()
        if !released {
            _ = close(directoryFD)
            _ = close(ownerFD)
        }
    }

    private struct Identity: Codable, Equatable {
        let inode: UInt64
        let device: Int32
        let birthSeconds: Int64
        let birthNanoseconds: Int64

        init(_ info: stat) {
            inode = UInt64(info.st_ino)
            device = info.st_dev
            birthSeconds = Int64(info.st_birthtimespec.tv_sec)
            birthNanoseconds = Int64(info.st_birthtimespec.tv_nsec)
        }

        static func at(_ path: String) -> Identity? {
            var info = stat()
            guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else { return nil }
            return Identity(info)
        }
    }

    private static func store(_ identity: Identity, in fd: Int32) throws {
        let record = try JSONEncoder().encode(identity)
        guard ftruncate(fd, 0) == 0,
              record.withUnsafeBytes({ pwrite(fd, $0.baseAddress, $0.count, 0) }) == record.count,
              fsync(fd) == 0 else { throw Failure.lost }
    }

    private static func recoverAbandoned(path: String, ownerFD: Int32) -> Bool {
        var bytes = [UInt8](repeating: 0, count: 512)
        let count = pread(ownerFD, &bytes, bytes.count, 0)
        guard count > 0,
              let owned = try? JSONDecoder().decode(Identity.self, from: Data(bytes.prefix(count))),
              Identity.at(path) == owned else { return false }
        // Only our abandoned inode can be removed. An unmarked CLI lock or a
        // replacement owner is left intact, regardless of its mtime.
        return rmdir(path) == 0
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
