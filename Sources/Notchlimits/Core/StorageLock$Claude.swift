import Darwin
import Foundation

/// Coordinates with Claude Code's secureStorage.mutate: mkdir `.storage-write.lock`
/// in the credentials directory and keep its mtime current while holding it.
final class StorageLock$Claude: @unchecked Sendable {
    enum Failure: Error { case busy, lost }

    private var path: String
    private let identity: Identity
    private static let ownerAttribute = "dev.ustinoff.notchlimits.lock-owner"
    private static let retirementAttribute = "dev.ustinoff.notchlimits.lock-retirement"
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

    convenience init(directory: URL, createParent: Bool = true) throws {
        try self.init(path: directory.appendingPathComponent(".storage-write.lock"), lifetime: 15,
                      createParent: createParent)
    }

    init(path url: URL, lifetime: TimeInterval, createParent: Bool = true) throws {
        if createParent {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        }
        path = url.path
        self.lifetime = lifetime
        // Keep flock on a stable inode. The directory's owner marker and this
        // sidecar contain no credentials.
        let fd = open(path + ".notchlimits-owner", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.busy }
        var keepFD = false
        defer { if !keepFD { _ = close(fd) } }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw Failure.busy }
        guard Self.finishRetirement(at: path, ownerFD: fd, lifetime: lifetime) else { throw Failure.busy }
        var existing = stat()
        if lstat(path, &existing) == 0 {
            guard Self.recoverAbandoned(path: path, ownerFD: fd, lifetime: lifetime) else {
                throw Failure.busy
            }
        } else if errno != ENOENT {
            throw Failure.busy
        }

        // Prepare a private empty directory and its complete identity before
        // exposing the native lock path. A crash during preparation cannot
        // leave an unmarked native lock behind.
        let prepared = url.deletingLastPathComponent()
            .appendingPathComponent("." + url.lastPathComponent + ".notchlimits-" + UUID().uuidString).path
        guard mkdir(prepared, 0o700) == 0 else { throw Failure.busy }
        defer { _ = rmdir(prepared) }
        var info = stat()
        guard lstat(prepared, &info) == 0 else { throw Failure.lost }
        let identity = Identity(info)
        let directory = open(prepared, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw Failure.lost }
        defer { if !keepFD { _ = close(directory) } }
        var opened = stat()
        guard fstat(directory, &opened) == 0, Identity(opened) == identity else { throw Failure.lost }
        guard Self.markOwner(directory) else { throw Failure.lost }
        // Never replace a native owner that acquired the path while preparing.
        guard renameatx_np(AT_FDCWD, prepared, AT_FDCWD, path, UInt32(RENAME_EXCL)) == 0 else {
            throw Failure.busy
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

    fileprivate func isHeld(at url: URL) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return !released && !heartbeatFailed && withinLease && ownsDirectory && ownsDirectory(at: url.path)
    }

    /// Rename a managed profile without making its pinned native locks appear
    /// lost to heartbeat or concurrent renewal checks during removal/rollback.
    static func moveDirectory(from: URL, to: URL, locks: [StorageLock$Claude]) throws {
        locks.forEach { $0.stateLock.lock() }
        defer { locks.reversed().forEach { $0.stateLock.unlock() } }
        guard locks.allSatisfy({
            !$0.released && !$0.heartbeatFailed && $0.withinLease && $0.ownsDirectory
                && $0.ownsDirectory(at: from.appendingPathComponent(URL(fileURLWithPath: $0.path).lastPathComponent).path)
        }) else {
            throw Failure.lost
        }
        try FileManager.default.moveItem(at: from, to: to)
        for lock in locks {
            // A moved symlink may be removed before release; retain its physical target.
            lock.path = to.resolvingSymlinksInPath().appendingPathComponent(URL(fileURLWithPath: lock.path).lastPathComponent).path
        }
    }

    private var ownsDirectory: Bool {
        ownsDirectory(at: path)
    }

    private func ownsDirectory(at path: String) -> Bool {
        // The held descriptor prevents inode reuse while alive. Birthtime is
        // checked only when recovering the previous JSON owner-record format.
        return identity.matches(Identity.at(path))
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
            guard futimes(directoryFD, nil) == 0, ownsDirectory else { throw Failure.lost }
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
        if Self.removeOwnedDirectory(at: path, identity: identity, ownerFD: ownerFD, lifetime: lifetime) {
            _ = ftruncate(ownerFD, 0)
        }
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

        func matches(_ current: Identity?) -> Bool {
            current?.inode == inode && current?.device == device
        }

        static func at(_ path: String, relativeTo directory: Int32 = AT_FDCWD) -> Identity? {
            var info = stat()
            guard fstatat(directory, path, &info, AT_SYMLINK_NOFOLLOW) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR else { return nil }
            return Identity(info)
        }
    }

    private static func markOwner(_ directory: Int32) -> Bool {
        let marker = Data(UUID().uuidString.utf8)
        return marker.withUnsafeBytes {
            fsetxattr(directory, ownerAttribute, $0.baseAddress, $0.count, 0, 0) == 0
        }
    }

    private struct Retirement: Codable {
        let id: UUID
        let original: Identity
        let placeholder: Identity
        var vacantSince: Date? = nil

        func stagedName(for name: String) -> String {
            "." + name + ".retiring-" + id.uuidString
        }
    }

    private static func removeOwnedDirectory(at path: String, identity: Identity, ownerFD: Int32,
                                             lifetime: TimeInterval) -> Bool {
        let url = URL(fileURLWithPath: path)
        let name = url.lastPathComponent
        let parent = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { return false }
        defer { _ = close(parent) }
        guard let original = Identity.at(name, relativeTo: parent), identity.matches(original) else { return false }

        let id = UUID()
        let staged = "." + name + ".retiring-" + id.uuidString
        guard mkdirat(parent, staged, 0o700) == 0 else { return false }
        let guardFD = openat(parent, staged, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard guardFD >= 0 else {
            _ = unlinkat(parent, staged, AT_REMOVEDIR)
            return false
        }
        defer { _ = close(guardFD) }
        var info = stat()
        guard fstat(guardFD, &info) == 0, markOwner(guardFD) else {
            _ = unlinkat(parent, staged, AT_REMOVEDIR)
            return false
        }
        let placeholder = Identity(info)
        func removeStaged(_ owner: Identity) -> Bool {
            owner.matches(Identity.at(staged, relativeTo: parent)) && unlinkat(parent, staged, AT_REMOVEDIR) == 0
        }

        // Keep the native name occupied while checking the inode that was moved.
        // The empty, marked placeholder is recoverable if Notchlimits crashes.
        guard identity.matches(Identity.at(name, relativeTo: parent)),
              recordRetirement(Retirement(id: id, original: original, placeholder: placeholder), ownerFD: ownerFD)
        else {
            _ = removeStaged(placeholder)
            return false
        }
        defer { _ = finishRetirement(name: name, parent: parent, ownerFD: ownerFD, lifetime: lifetime) }
        guard identity.matches(Identity.at(name, relativeTo: parent)),
              renameatx_np(parent, name, parent, staged, UInt32(RENAME_SWAP)) == 0 else {
            _ = removeStaged(placeholder)
            return false
        }
        guard removeStaged(identity) else { return false }

        // Detach the placeholder before removing it as well. Any native
        // directory caught by the move is subject to the same lease expiry.
        guard placeholder.matches(Identity.at(name, relativeTo: parent)),
              renameatx_np(parent, name, parent, staged, UInt32(RENAME_EXCL)) == 0 else { return false }
        return removeStaged(placeholder)
    }

    private static func recordRetirement(_ retirement: Retirement, ownerFD: Int32) -> Bool {
        guard let data = try? JSONEncoder().encode(retirement) else { return false }
        return data.withUnsafeBytes {
            fsetxattr(ownerFD, retirementAttribute, $0.baseAddress, $0.count, 0, 0) == 0
        }
    }

    private static func finishRetirement(at path: String, ownerFD: Int32, lifetime: TimeInterval) -> Bool {
        let url = URL(fileURLWithPath: path)
        let parent = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { return false }
        defer { _ = close(parent) }
        return finishRetirement(name: url.lastPathComponent, parent: parent, ownerFD: ownerFD, lifetime: lifetime)
    }

    private static func finishRetirement(name: String, parent: Int32, ownerFD: Int32, lifetime: TimeInterval) -> Bool {
        var bytes = [UInt8](repeating: 0, count: 512)
        let count = bytes.withUnsafeMutableBytes {
            fgetxattr(ownerFD, retirementAttribute, $0.baseAddress, $0.count, 0, 0)
        }
        if count < 0 { return errno == ENOATTR }
        guard var retirement = try? JSONDecoder().decode(Retirement.self, from: Data(bytes.prefix(count))) else {
            return false
        }
        let staged = retirement.stagedName(for: name)
        func clearRecord() -> Bool {
            fremovexattr(ownerFD, retirementAttribute, 0) == 0
        }
        var info = stat()
        if fstatat(parent, staged, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            return errno == ENOENT && clearRecord()
        }
        let displaced = Identity(info)
        if displaced == retirement.original || displaced == retirement.placeholder {
            guard unlinkat(parent, staged, AT_REMOVEDIR) == 0 else { return false }
            return clearRecord()
        }
        // A native lock has no owner record. The client can still heartbeat or
        // release at the public name. Let the lease expire without moving that
        // name or publishing an old owner over a vacancy.
        guard info.st_mode & S_IFMT == S_IFDIR else { return false }
        let now = Date()
        let modified = modificationDate(info)
        var publicInfo = stat()
        if fstatat(parent, name, &publicInfo, AT_SYMLINK_NOFOLLOW) == 0 {
            if retirement.vacantSince != nil {
                retirement.vacantSince = nil
                guard recordRetirement(retirement, ownerFD: ownerFD) else { return false }
            }
            guard Identity(publicInfo) == retirement.placeholder,
                  now.timeIntervalSince(max(modified, modificationDate(publicInfo))) >= lifetime else { return false }
        } else {
            guard errno == ENOENT else { return false }
            guard let vacantSince = retirement.vacantSince else {
                retirement.vacantSince = now
                _ = recordRetirement(retirement, ownerFD: ownerFD)
                return false
            }
            guard now.timeIntervalSince(max(modified, vacantSince)) >= lifetime else { return false }
        }
        return unlinkat(parent, staged, AT_REMOVEDIR) == 0 && clearRecord()
    }

    private static func modificationDate(_ info: stat) -> Date {
        Date(timeIntervalSince1970: Double(info.st_mtimespec.tv_sec) + Double(info.st_mtimespec.tv_nsec) / 1_000_000_000)
    }

    private static func hasOwnerMarker(_ directory: Int32) -> Bool {
        var bytes = [UInt8](repeating: 0, count: 64)
        let count = bytes.withUnsafeMutableBytes {
            fgetxattr(directory, ownerAttribute, $0.baseAddress, $0.count, 0, 0)
        }
        guard count > 0, let value = String(bytes: bytes.prefix(count), encoding: .utf8) else { return false }
        return UUID(uuidString: value) != nil
    }

    private static func readIdentity(_ fd: Int32) -> Identity? {
        var bytes = [UInt8](repeating: 0, count: 512)
        let count = pread(fd, &bytes, bytes.count, 0)
        guard count > 0 else { return nil }
        return try? JSONDecoder().decode(Identity.self, from: Data(bytes.prefix(count)))
    }

    private static func recoverAbandoned(path: String, ownerFD: Int32, lifetime: TimeInterval) -> Bool {
        // Extended attributes keep the native lock directory empty for rmdir.
        // The marker is set atomically before publishing the directory and is
        // never rewritten by heartbeats. Also accept the previous JSON format.
        let directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { return false }
        defer { _ = close(directory) }
        var info = stat()
        guard fstat(directory, &info) == 0 else { return false }
        let identity = Identity(info)
        let marked = hasOwnerMarker(directory)
        let legacy = readIdentity(ownerFD) == identity
        guard marked || legacy else { return false }
        return removeOwnedDirectory(at: path, identity: identity, ownerFD: ownerFD, lifetime: lifetime)
    }
}

/// Claude Code holds both locks across read, refresh and persistence. The legacy
/// lock uses the real config path, including for symlinked profile directories.
final class RefreshLock$Claude: @unchecked Sendable {
    private final class Active {
        weak var lease: RefreshLock$Claude?
        init(_ lease: RefreshLock$Claude) { self.lease = lease }
    }
    private static let registryLock = NSLock()
    private static var active: [String: Active] = [:]
    private static var owners: [Active] = []
    private let current: StorageLock$Claude
    private let legacy: StorageLock$Claude
    private let directoryKey: String
    private let releaseLock = NSLock()
    private let fileOwnerLock = NSLock()
    private var fileOwner: DirectoryIdentity?

    init(directory: URL, createParent: Bool) throws {
        directoryKey = directory.resolvingSymlinksInPath().path
        if createParent {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        fileOwner = DirectoryIdentity.capture(directory)
        current = try StorageLock$Claude(path: directory.appendingPathComponent(".oauth_refresh.lock"),
                                        lifetime: 60, createParent: false)
        do {
            let path = directory.resolvingSymlinksInPath().path + ".lock"
            legacy = try StorageLock$Claude(path: URL(fileURLWithPath: path), lifetime: 60, createParent: false)
        } catch {
            current.release()
            throw error
        }
        Self.registryLock.lock()
        Self.active[directoryKey] = Active(self)
        Self.owners.removeAll { $0.lease == nil }
        Self.owners.append(Active(self))
        Self.registryLock.unlock()
    }

    /// Removal may borrow our renewal lease, but must never bypass a native owner.
    /// Keep that lease from being released until the synchronous mutation ends.
    static func withRemovalLock(directory: URL, createParent: Bool,
                                operation: (RefreshLock$Claude) throws -> Void) throws {
        let key = directory.resolvingSymlinksInPath().path
        registryLock.lock()
        let existing = active[key]?.lease
        registryLock.unlock()
        let lease = try existing ?? RefreshLock$Claude(directory: directory, createParent: createParent)
        defer { if existing == nil { lease.release() } }
        lease.releaseLock.lock()
        defer { lease.releaseLock.unlock() }
        guard lease.isHeld, lease.current.isHeld(at: directory.appendingPathComponent(".oauth_refresh.lock")) else {
            throw StorageLock$Claude.Failure.busy
        }
        try operation(lease)
    }

    var isHeld: Bool { current.isHeld && legacy.isHeld }

    /// Keep accepted file rotations attached to authorized removal/rollback moves.
    var fileDirectory: DirectoryIdentity? {
        fileOwnerLock.lock()
        defer { fileOwnerLock.unlock() }
        return fileOwner
    }

    static func recordRestoredFileOwner(from source: URL, to destination: URL) {
        guard let original = DirectoryIdentity.capture(source),
              let restored = DirectoryIdentity.capture(destination) else { return }
        moveFileOwners(from: original, to: restored)
    }

    /// A pending grant can retain its owner after releasing a lost lease.
    /// Authorized moves update that owner without making the old lease borrowable.
    private static func moveFileOwners(from original: DirectoryIdentity, to restored: DirectoryIdentity) {
        registryLock.lock()
        owners.removeAll { $0.lease == nil }
        let leases = owners.compactMap(\.lease)
        registryLock.unlock()
        for lease in leases {
            lease.fileOwnerLock.lock()
            if lease.fileOwner?.isSameDirectory(as: original) == true { lease.fileOwner = restored }
            lease.fileOwnerLock.unlock()
        }
    }

    func moveDirectory(from: URL, to: URL, storage: StorageLock$Claude) throws {
        guard let original = DirectoryIdentity.capture(from) else { throw StorageLock$Claude.Failure.lost }
        // The legacy OAuth lock is adjacent to the profile and stays in place.
        try StorageLock$Claude.moveDirectory(from: from, to: to, locks: [current, storage])
        if let restored = DirectoryIdentity.capture(to), restored.isSameDirectory(as: original) {
            Self.moveFileOwners(from: original, to: restored)
        }
    }

    func onLost(_ handler: @escaping () -> Void) {
        current.onLost(handler)
        legacy.onLost(handler)
    }

    func release() {
        releaseLock.lock()
        defer { releaseLock.unlock() }
        legacy.release()
        current.release()
        Self.registryLock.lock()
        if Self.active[directoryKey]?.lease === self { Self.active[directoryKey] = nil }
        Self.registryLock.unlock()
    }
}
