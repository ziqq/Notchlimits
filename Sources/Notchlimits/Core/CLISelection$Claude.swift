import CryptoKit
import Foundation
import Darwin

/// Route new CLI invocations to existing profiles without copying credentials.
/// The shell reads a persistent selection, so Claude works when Notchlimits is closed.
enum CLISelection$Claude {
    static let enabledKey = "switchClaudeCLI"

    static var isEnabled: Bool {
        get { UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey) }
    }

    private static var root: URL {
        DesktopApp.supportDirectory.appendingPathComponent("claude-cli", isDirectory: true)
    }

    private static var pointer: URL { root.appendingPathComponent("selected-profile") }
    private static var retirement: URL { root.appendingPathComponent(".retired-profile") }
    private static let retirementAttribute = "dev.ustinoff.notchlimits.cli-retirement"
    private static let parkedPrefix = ".retired-directory-"

    private struct Failure: LocalizedError {
        let errorDescription: String?
    }

    private struct ProfileIdentity: Codable, Equatable {
        let path: String
        let device: Int32
        let inode: UInt64
        let birthSeconds: Int64
        let birthNanoseconds: Int64

        init?(_ profile: URL, resolving: Bool = true) {
            path = resolving ? profile.resolvingSymlinksInPath().path : profile.path
            var info = stat()
            guard lstat(path, &info) == 0,
                  info.st_mode & S_IFMT == S_IFDIR || !resolving && info.st_mode & S_IFMT == S_IFLNK else { return nil }
            device = info.st_dev
            inode = UInt64(info.st_ino)
            birthSeconds = Int64(info.st_birthtimespec.tv_sec)
            birthNanoseconds = Int64(info.st_birthtimespec.tv_nsec)
        }

        func isSameNode(as other: Self?) -> Bool {
            device == other?.device && inode == other?.inode
                && birthSeconds == other?.birthSeconds && birthNanoseconds == other?.birthNanoseconds
        }
    }

    private struct DirectoryMove: Codable, Equatable {
        let parent: ProfileIdentity
        let originalName: String
        let stagedName: String
        let entry: ProfileIdentity
        let hadFileLogin: Bool
        var fallbackFile: String?

        init?(from source: URL, to stage: URL, owner: ProfileIdentity) {
            guard let parent = ProfileIdentity(source.deletingLastPathComponent()),
                  ProfileIdentity(stage.deletingLastPathComponent()) == parent, ProfileIdentity(source) == owner,
                  let entry = ProfileIdentity(source, resolving: false), DirectoryIdentity.missingPath(stage) != nil,
                  let hadFileLogin = Self.fileLoginExists(at: source) else { return nil }
            self.parent = parent
            originalName = source.lastPathComponent
            stagedName = stage.lastPathComponent
            self.entry = entry
            self.hadFileLogin = hadFileLogin
            if hadFileLogin, let owner = DirectoryIdentity.capture(source) {
                fallbackFile = CLISelection$Claude.credentialFileProof(in: owner)
            }
        }

        private var directory: URL { URL(fileURLWithPath: parent.path, isDirectory: true) }
        var original: URL { directory.appendingPathComponent(originalName, isDirectory: true) }
        var staged: URL { directory.appendingPathComponent(stagedName, isDirectory: true) }

        private func ownsStage(_ owner: ProfileIdentity) -> Bool {
            !originalName.hasPrefix(".") && !originalName.contains("/") && originalName != ""
                && stagedName.hasPrefix(".removed-") && !stagedName.contains("/")
                && UUID(uuidString: String(stagedName.dropFirst(".removed-".count))) != nil
                && ProfileIdentity(directory) == parent
                && entry.isSameNode(as: ProfileIdentity(staged, resolving: false))
                && owner.isSameNode(as: ProfileIdentity(staged))
        }

        func canRestore(to profile: URL, owner: ProfileIdentity) -> Bool {
            ownsStage(owner)
                && (Self.fileLoginExists(at: staged) == hadFileLogin || hasIsolatedFallback)
                && DirectoryIdentity.missingPath(original) != nil
                && DirectoryIdentity.missingPath(profile) != nil
        }

        var hasIsolatedFallback: Bool {
            Self.fileLoginExists(at: staged) == false && hasFallbackCheckpoint
        }

        private var hasFallbackCheckpoint: Bool {
            guard let fallbackFile, let owner = DirectoryIdentity.capture(staged) else { return false }
            return CLISelection$Claude.credentialFileProof(in: owner, name: AccountRemoval.claudeFallbackName(staged))
                == fallbackFile
        }

        func fileWasMoved(to profile: URL, owner: ProfileIdentity) -> Bool {
            hadFileLogin && ownsStage(owner)
                && Self.fileLoginExists(at: staged) == false
                && Self.fileLoginExists(at: profile) == true
        }

        func ownsIsolatedFallback(_ owner: ProfileIdentity) -> Bool {
            ownsStage(owner) && hasIsolatedFallback
        }

        func ownsFallbackCheckpoint(_ owner: ProfileIdentity) -> Bool {
            ownsStage(owner) && hasFallbackCheckpoint
        }

        private static func fileLoginExists(at directory: URL) -> Bool? {
            var info = stat()
            if lstat(directory.appendingPathComponent(".credentials.json").path, &info) == 0 { return true }
            return errno == ENOENT ? false : nil
        }
    }

    private struct RetirementProof: Codable {
        let selection: String
        let owner: ProfileIdentity
        let fromFile: Bool
        let fingerprint: Data?
        var stub: Data?
        var opaqueKeychain: AuthStorage$Claude.RemovalKeychainProof?
        var directoryMove: DirectoryMove?
        var recoveryService: String?
        var rollbackCredentialFile: String?

        init?(selection: String, owner: DirectoryIdentity, credentials: AuthStorage$Claude.Credentials) {
            self.selection = selection
            let profile = URL(fileURLWithPath: selection)
            guard let identity = ProfileIdentity(profile), owner.matches(profile),
                  credentials.backend != .file || credentials.directory == owner,
                  let fingerprint = Self.fingerprint(credentials) else { return nil }
            self.owner = identity
            fromFile = credentials.backend == .file
            self.fingerprint = fingerprint
        }

        init?(selection: String, owner: DirectoryIdentity, nonOAuth: AuthStorage$Claude.DesktopLoginProof) {
            let profile = URL(fileURLWithPath: selection)
            guard let identity = ProfileIdentity(profile), owner.matches(profile),
                  nonOAuth.stub != nil || nonOAuth.opaqueKeychain != nil else { return nil }
            self.selection = selection
            self.owner = identity
            fromFile = false
            fingerprint = nil
            stub = nonOAuth.stub
            opaqueKeychain = nonOAuth.opaqueKeychain
        }

        private static func fingerprint(_ credentials: AuthStorage$Claude.Credentials) -> Data? {
            guard let tokens = try? JSONEncoder().encode([credentials.accessToken, credentials.refreshToken]) else { return nil }
            return Data(SHA256.hash(data: tokens))
        }

        func matches(_ credentials: AuthStorage$Claude.Credentials) -> Bool {
            fingerprint != nil && fromFile == (credentials.backend == .file) && Self.fingerprint(credentials) == fingerprint
        }

        func matchesCurrent(directory: DirectoryIdentity? = nil) throws -> Bool {
            if let opaqueKeychain {
                return AuthStorage$Claude.removalKeychainProof(service: service) == opaqueKeychain
            }
            if let stub {
                let path = directory?.path ?? selection
                let current = AuthStorage$Claude.desktopLoginProof(service: service, directory: URL(fileURLWithPath: path),
                                                                   keychainOnly: false)
                return current?.stub == stub
            }
            guard let credentials = AuthStorage$Claude.credentials(service: service, interactive: false,
                                                                   verifyingOwner: true, directory: directory),
                  matches(credentials) else { return false }
            return try AuthStorage$Claude.isCurrent(credentials, service: service, directory: directory)
        }

        var service: String {
            recoveryService ?? AuthStorage$Claude.profileService(forConfigPath: selection)
        }

        func matchesRoute() -> Bool {
            if recoveryService != nil {
                return AuthStorage$Claude.configDirectory(for: service).flatMap { ProfileIdentity($0) } == owner
            }
            return AuthStorage$Claude.configPath(for: service) == selection
        }
    }

    /// Replace or recover the pointer under one lock. The shell only needs
    /// its atomically published path and never reads Keychain itself.
    private static func withSelectionLock<T>(_ operation: () throws -> T) throws -> T? {
        let lock = root.appendingPathComponent(".selection-lock")
        let descriptor = open(lock.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { _ = close(descriptor) }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        return try operation()
    }

    private static func selection(at file: FileHandle) -> String? {
        (try? file.readToEnd()).flatMap { data in
            String(data: data, encoding: .utf8)?
                .split(separator: "\n", omittingEmptySubsequences: false).first.map(String.init)
        }
    }

    /// Bind recovery evidence to the same inode as the selection, so a cut
    /// between recording it and moving that inode leaves the live pointer intact.
    private static func writeProof(_ proof: RetirementProof?, descriptor: Int32) throws {
        if let proof {
            let data = try PropertyListEncoder().encode(proof)
            guard data.withUnsafeBytes({ fsetxattr(descriptor, retirementAttribute, $0.baseAddress, $0.count, 0, 0) }) == 0
            else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        } else if fremovexattr(descriptor, retirementAttribute, 0) != 0, errno != ENOATTR {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    private static func readProof(_ file: FileHandle) -> RetirementProof? {
        var bytes = Data(count: 8192)
        let size = bytes.withUnsafeMutableBytes {
            fgetxattr(file.fileDescriptor, retirementAttribute, $0.baseAddress, $0.count, 0, 0)
        }
        guard size > 0, let proof = try? PropertyListDecoder().decode(RetirementProof.self, from: bytes.prefix(size)),
              proof.selection.hasPrefix("/"), selection(at: file) == proof.selection else { return nil }
        return proof
    }

    private static func retirementFile(at receipt: URL, writable: Bool = false) -> FileHandle? {
        let mode = writable ? O_RDWR : O_RDONLY
        let descriptor = open(receipt.path, mode | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        return descriptor < 0 ? nil : FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private static func isSameFile(_ descriptor: Int32, at url: URL) -> Bool {
        var pinned = stat(), current = stat()
        return fstat(descriptor, &pinned) == 0 && pinned.st_mode & S_IFMT == S_IFREG
            && lstat(url.path, &current) == 0 && current.st_dev == pinned.st_dev && current.st_ino == pinned.st_ino
    }

    private static func credentialFileProof(in owner: DirectoryIdentity, name: String = ".credentials.json") -> String? {
        let descriptor = open(owner.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { _ = close(descriptor) }
        guard DirectoryIdentity.capture(descriptor: descriptor) == owner else { return nil }
        return AppSwitcher$Claude.credentialFileProof(descriptor, name: name)
    }

    private static func matchesRollbackFile(_ proof: RetirementProof, profile: URL) -> Bool {
        guard let expected = proof.rollbackCredentialFile else { return true }
        guard let owner = DirectoryIdentity.capture(profile) else { return false }
        return credentialFileProof(in: owner) == expected
    }

    /// Keep the exact receipt if the previous directory still needs recovery.
    /// A parked receipt has no authority to publish a CLI selection.
    private static func parkSupersededRetirement() throws {
        guard let file = retirementFile(at: retirement) else {
            if DirectoryIdentity.missingPath(retirement) != nil { return }
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        guard isSameFile(file.fileDescriptor, at: retirement) else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        if let proof = readProof(file), proof.directoryMove == nil {
            guard unlink(retirement.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        } else {
            try moveSelection(from: retirement, to: root.appendingPathComponent(parkedPrefix + UUID().uuidString))
        }
    }

    private static func parkedRetirements() -> [URL] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []
        return names.compactMap { name in
            guard name.hasPrefix(parkedPrefix),
                  UUID(uuidString: String(name.dropFirst(parkedPrefix.count))) != nil else { return nil }
            return root.appendingPathComponent(name)
        }
    }

    /// An independently re-added login retires this receipt's authority over
    /// the name. Keep the receipt and staged directory for manual recovery.
    private static func archiveIfReplaced(_ receipt: URL, file: FileHandle, proof: RetirementProof,
                                          owner: DirectoryIdentity) throws {
        let profile = URL(fileURLWithPath: proof.selection)
        guard proof.directoryMove != nil, proof.opaqueKeychain == nil, ProfileIdentity(profile) != proof.owner,
              owner.matches(profile),
              let routed = AuthStorage$Claude.configDirectory(for: proof.service), owner.matches(routed),
              let credentials = AuthStorage$Claude.credentials(service: proof.service, interactive: false,
                                                               verifyingOwner: true, directory: owner),
              !proof.matches(credentials),
              (try? AuthStorage$Claude.isCurrent(credentials, service: proof.service, directory: owner)) == true,
              owner.matches(profile), isSameFile(file.fileDescriptor, at: receipt) else { return }
        let archived = root.appendingPathComponent(".superseded-retirement-" + UUID().uuidString)
        try moveSelection(from: receipt, to: archived)
    }

    private static func archiveReplacedRetirements(at source: URL) throws {
        guard let owner = DirectoryIdentity.capture(source) else { return }
        for receipt in [retirement] + parkedRetirements() {
            guard let file = retirementFile(at: receipt), let proof = readProof(file) else { continue }
            try archiveIfReplaced(receipt, file: file, proof: proof, owner: owner)
        }
    }

    /// Called by real discovery on startup and later polls. An old random
    /// .retired-* file cannot prove which directory or login owned the route.
    static func recoverInterruptedRetirement() {
        if let file = retirementFile(at: retirement), FileManager.default.fileExists(atPath: pointer.path) {
            // A cut can leave the just-published pointer beside the old receipt.
            _ = try? withSelectionLock {
                guard FileManager.default.fileExists(atPath: pointer.path),
                      isSameFile(file.fileDescriptor, at: retirement) else { return }
                try parkSupersededRetirement()
            }
        }
        recoverRetirement(at: retirement, publishSelection: true)
        for receipt in parkedRetirements() {
            recoverRetirement(at: receipt, publishSelection: false)
        }
    }

    /// Desktop must retain a verified file transfer until the selected route
    /// adopts the new directory or an explicit selection supersedes recovery.
    static func requiresDesktopRollbackProof(service: String) -> Bool {
        guard DirectoryIdentity.missingPath(pointer) != nil,
              let file = retirementFile(at: retirement), let proof = readProof(file),
              proof.service == service, proof.fromFile, proof.recoveryService == nil,
              let move = proof.directoryMove else { return false }
        let profile = URL(fileURLWithPath: proof.selection)
        return ProfileIdentity(profile) != proof.owner && move.fileWasMoved(to: profile, owner: proof.owner)
            && isSameFile(file.fileDescriptor, at: retirement)
    }

    private static func recoverRetirement(at receipt: URL, publishSelection: Bool) {
        guard let file = retirementFile(at: receipt), let proof = readProof(file) else { return }
        let profile = URL(fileURLWithPath: proof.selection)
        let service = proof.service
        guard !publishSelection || DirectoryIdentity.missingPath(pointer) != nil else { return }
        if let move = proof.directoryMove, !proof.fromFile, move.ownsFallbackCheckpoint(proof.owner),
           AuthStorage$Claude.removalKeychainIsAbsent(service: service) {
            try? finishCommittedFallback(move, proof: proof, receipt: receipt, file: file)
            return
        }
        if ProfileIdentity(profile) != proof.owner {
            if let owner = DirectoryIdentity.capture(profile) {
                if publishSelection, proof.fromFile,
                   proof.directoryMove?.fileWasMoved(to: profile, owner: proof.owner) == true {
                    try? recoverRestoredFileSelection(proof: proof, file: file, profile: profile, owner: owner)
                }
                _ = try? withSelectionLock {
                    try archiveIfReplaced(receipt, file: file, proof: proof, owner: owner)
                }
                return
            }
            guard let move = proof.directoryMove, move.canRestore(to: profile, owner: proof.owner) else { return }
            try? recoverStagedRetirement(move, receipt: receipt, publishSelection: publishSelection,
                                         proof: proof, profile: profile, service: service)
            return
        }
        if !publishSelection {
            _ = try? withSelectionLock {
                if ProfileIdentity(profile) == proof.owner, isSameFile(file.fileDescriptor, at: receipt) {
                    _ = unlink(receipt.path)
                }
            }
            return
        }
        try? AuthStorage$Claude.withRemovalLock(directory: profile, validating: { _, validate in
            _ = try withSelectionLock {
                guard DirectoryIdentity.missingPath(pointer) != nil,
                      isSameFile(file.fileDescriptor, at: receipt),
                      let current = retirementFile(at: receipt), let saved = readProof(current),
                      saved.selection == proof.selection, saved.recoveryService == nil,
                      ProfileIdentity(profile) == saved.owner, saved.matchesRoute(), matchesRollbackFile(saved, profile: profile),
                      try saved.matchesCurrent()
                else { return }
                try validate()
                guard ProfileIdentity(profile) == saved.owner, matchesRollbackFile(saved, profile: profile),
                      isSameFile(current.fileDescriptor, at: receipt) else { return }
                try moveSelection(from: receipt, to: pointer)
            }
        })
    }

    private static func recoverRestoredFileSelection(proof: RetirementProof, file: FileHandle,
                                                     profile: URL, owner: DirectoryIdentity) throws {
        try AuthStorage$Claude.withRemovalLock(directory: profile, validating: { _, validate in
            _ = try withSelectionLock {
                guard DirectoryIdentity.missingPath(pointer) != nil, owner.matches(profile),
                      isSameFile(file.fileDescriptor, at: retirement),
                      let current = retirementFile(at: retirement, writable: true), let saved = readProof(current),
                      saved.selection == proof.selection, saved.owner == proof.owner, saved.fromFile,
                      saved.recoveryService == nil, let move = saved.directoryMove, move == proof.directoryMove,
                      move.fileWasMoved(to: profile, owner: saved.owner),
                      let previous = DirectoryIdentity.capture(move.staged), saved.matchesRoute(),
                      let credentials = AuthStorage$Claude.credentials(service: saved.service, interactive: false, verifyingOwner: true),
                      saved.matches(credentials), try AuthStorage$Claude.isCurrent(credentials, service: saved.service),
                      let credentialFile = credentialFileProof(in: owner),
                      AppSwitcher$Claude.verifiedFileRollback(service: saved.service, previous: previous, restored: owner),
                      var rebound = RetirementProof(selection: saved.selection, owner: owner, credentials: credentials)
                else { return }
                try validate()
                guard isSameFile(current.fileDescriptor, at: retirement),
                      move.fileWasMoved(to: profile, owner: saved.owner),
                      credentialFileProof(in: owner) == credentialFile else { return }
                rebound.rollbackCredentialFile = credentialFile
                try writeProof(rebound, descriptor: current.fileDescriptor)
                try validate()
                guard owner.matches(profile), isSameFile(current.fileDescriptor, at: retirement),
                      credentialFileProof(in: owner) == credentialFile else { return }
                try moveSelection(from: retirement, to: pointer)
            }
        })
    }

    private static func recoverStagedRetirement(_ move: DirectoryMove, receipt: URL, publishSelection: Bool,
                                                proof: RetirementProof, profile: URL, service: String) throws {
        try AuthStorage$Claude.withRemovalLock(directory: move.staged, exclusiveMove: true, validating: { restore, validate in
            // The old legacy lock stayed beside the original directory. A
            // staged symlink resolving to that same target already holds it.
            let legacy = move.staged.resolvingSymlinksInPath().path == proof.owner.path ? nil : try StorageLock$Claude(
                path: URL(fileURLWithPath: proof.owner.path + ".lock"), lifetime: 60, createParent: false)
            defer { legacy?.release() }
            _ = try withSelectionLock {
                guard !publishSelection || DirectoryIdentity.missingPath(pointer) != nil,
                      let file = retirementFile(at: receipt), let saved = readProof(file),
                      saved.selection == proof.selection, saved.service == service,
                      let move = saved.directoryMove, move == proof.directoryMove,
                      move.canRestore(to: profile, owner: saved.owner),
                      let owner = DirectoryIdentity.capture(move.staged),
                      try saved.matchesCurrent(directory: owner)
                else { return }
                try validate()
                guard legacy?.isHeld != false, move.canRestore(to: profile, owner: saved.owner),
                      isSameFile(file.fileDescriptor, at: receipt) else { return }
                if let fallback = move.fallbackFile, move.hasIsolatedFallback {
                    try AccountRemoval.resolveClaudeFallback(in: move.staged, matching: fallback, restoring: true) {
                        try validate()
                        guard legacy?.isHeld != false, move.ownsIsolatedFallback(saved.owner),
                              try saved.matchesCurrent(directory: owner) else {
                            throw Failure(errorDescription: L.t("error.cliProfile"))
                        }
                    }
                    guard credentialFileProof(in: owner) == fallback else { return }
                } else if move.ownsFallbackCheckpoint(saved.owner) {
                    return
                }
                try restore(move.staged, move.original)
                guard ProfileIdentity(profile) == saved.owner,
                      saved.matchesRoute(),
                      try saved.matchesCurrent()
                else { return }
                try validate()
                guard legacy?.isHeld != false, ProfileIdentity(profile) == saved.owner,
                      isSameFile(file.fileDescriptor, at: receipt) else { return }
                if publishSelection { try moveSelection(from: receipt, to: pointer) }
                else { _ = unlink(receipt.path) }
            }
        })
    }

    private static func finishCommittedFallback(_ move: DirectoryMove, proof: RetirementProof, receipt: URL,
                                                file: FileHandle) throws {
        guard let fallback = move.fallbackFile else { return }
        try AuthStorage$Claude.withRemovalLock(directory: move.staged, validating: { _, validate in
            _ = try withSelectionLock {
                try AccountRemoval.resolveClaudeFallback(in: move.staged, matching: fallback, restoring: false) {
                    try validate()
                    guard isSameFile(file.fileDescriptor, at: receipt), move.ownsFallbackCheckpoint(proof.owner),
                          AuthStorage$Claude.removalKeychainIsAbsent(service: proof.service) else {
                        throw Failure(errorDescription: L.t("error.cliProfile"))
                    }
                }
                _ = unlink(receipt.path)
            }
        })
    }

    private static func clearFinishedRetirement(_ receipt: URL) {
        if let file = retirementFile(at: receipt), let proof = readProof(file),
           proof.directoryMove?.ownsFallbackCheckpoint(proof.owner) == true {
            // Keep the receipt when cleanup has been refused. Discovery can
            // finish the isolated file without exposing it as a login.
            return
        }
        _ = unlink(receipt.path)
    }

    /// An old shell must refuse a retired extra profile even after its path is
    /// reused. Keep the native default and any other selected profile intact.
    static func withRetiredSelection(services: Set<String>, directoryRecoveryService: String? = nil,
                                     operation: (_ fileRestored: @escaping (Int32, Int32) -> Void,
                                                 _ beforeMove: @escaping (URL, URL) throws -> String?) throws -> Void) throws {
        guard services.contains(where: { $0 != AuthStorage$Claude.baseService }) else {
            try operation({ _, _ in }, { _, _ in nil })
            return
        }
        if directoryRecoveryService != nil {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        let completed = try withSelectionLock {
            try retireSelection(services: services, directoryRecoveryService: directoryRecoveryService,
                                operation: operation)
            return true
        }
        if completed == nil {
            guard directoryRecoveryService == nil else { throw Failure(errorDescription: L.t("error.cliProfile")) }
            try operation({ _, _ in }, { _, _ in nil })
        }
    }

    private static func retireSelection(services: Set<String>, directoryRecoveryService: String?,
                                        operation: (_ fileRestored: @escaping (Int32, Int32) -> Void,
                                                    _ beforeMove: @escaping (URL, URL) throws -> String?) throws -> Void) throws {
        func withoutSelectedRetirement() throws {
            var receipt: URL?
            try operation({ _, _ in }, { source, stage in
                try archiveReplacedRetirements(at: source)
                guard let directoryRecoveryService else { return nil }
                let recorded = try recordUnselectedMove(service: directoryRecoveryService, source: source, stage: stage)
                receipt = recorded.receipt
                return recorded.fallback
            })
            if let receipt { clearFinishedRetirement(receipt) }
        }

        let descriptor = open(pointer.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else {
            guard errno == ENOENT else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            try withoutSelectedRetirement()
            return
        }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard isSameFile(descriptor, at: pointer) else { throw Failure(errorDescription: L.t("error.cliProfile")) }
        guard let selection = selection(at: file), selection.hasPrefix("/") else {
            try withoutSelectedRetirement()
            return
        }
        let service = AuthStorage$Claude.profileService(forConfigPath: selection)
        guard services.contains(service) else {
            try withoutSelectedRetirement()
            return
        }
        let profile = URL(fileURLWithPath: selection)
        let owner = DirectoryIdentity.capture(profile)
        let selectionIsCurrent = AuthStorage$Claude.captureSelectionRevision(for: service)
        var credentials = AuthStorage$Claude.credentials(service: service, interactive: false, verifyingOwner: true)
        var restoredOwner: DirectoryIdentity?
        let proof = owner.flatMap {
            retirementProof(service: service, selection: selection, owner: $0, credentials: credentials)
        }
        guard directoryRecoveryService == nil || proof != nil else { throw Failure(errorDescription: L.t("error.cliProfile")) }
        try writeProof(proof, descriptor: descriptor)
        // An existing live selection supersedes an earlier retirement.
        try parkSupersededRetirement()
        guard isSameFile(descriptor, at: pointer) else { throw Failure(errorDescription: L.t("error.cliProfile")) }
        try moveSelection(from: pointer, to: retirement)
        do {
            try operation({ source, destination in
                guard credentials?.backend == .file, let owner, credentials?.directory == owner,
                      let stagedOwner = DirectoryIdentity.capture(descriptor: source),
                      stagedOwner.isSameDirectory(as: owner) else { return }
                restoredOwner = DirectoryIdentity.capture(descriptor: destination)
            }, { source, stage in
                try archiveReplacedRetirements(at: source)
                guard var proof else { return nil }
                guard try proof.matchesCurrent(),
                      let move = DirectoryMove(from: source, to: stage, owner: proof.owner),
                      isSameFile(descriptor, at: retirement) else { throw Failure(errorDescription: L.t("error.cliProfile")) }
                proof.directoryMove = move
                try writeProof(proof, descriptor: descriptor)
                return move.fallbackFile
            })
        } catch {
            // A failed deletion can leave a different login at the same path.
            guard isSameFile(descriptor, at: retirement) else { throw error }
            if owner?.matches(profile) == true,
               selectionIsCurrent() || (try? proof?.matchesCurrent()) == true {
                try moveSelection(from: retirement, to: pointer)
                throw error
            }
            let rollbackOwner = owner?.matches(profile) == true ? owner : restoredOwner
            if credentials?.backend == .file { credentials?.directory = rollbackOwner }
            guard let rollbackOwner, let credentials, rollbackOwner.matches(profile),
                  (try? AuthStorage$Claude.isCurrent(credentials, service: service)) == true,
                  let rollbackProof = RetirementProof(selection: selection, owner: rollbackOwner, credentials: credentials)
            else { throw error }
            try writeProof(rollbackProof, descriptor: descriptor)
            guard rollbackOwner.matches(profile), isSameFile(descriptor, at: retirement) else { throw error }
            try moveSelection(from: retirement, to: pointer)
            throw error
        }
        clearFinishedRetirement(retirement)
    }

    private static func retirementProof(service: String, selection: String, owner: DirectoryIdentity,
                                        credentials: AuthStorage$Claude.Credentials?) -> RetirementProof? {
        if let credentials {
            return RetirementProof(selection: selection, owner: owner, credentials: credentials)
        }
        guard let known = AuthStorage$Claude.desktopLoginProof(service: service, directory: URL(fileURLWithPath: owner.path),
                                                               keychainOnly: false) else { return nil }
        return RetirementProof(selection: selection, owner: owner, nonOAuth: known)
    }

    private static func recordUnselectedMove(service: String, source: URL, stage: URL) throws
        -> (receipt: URL, fallback: String?) {
        guard !source.path.contains("\n"), !source.path.contains("\r"),
              let owner = DirectoryIdentity.capture(source),
              var proof = retirementProof(service: service, selection: source.path, owner: owner,
                                          credentials: AuthStorage$Claude.credentials(service: service, interactive: false,
                                                                                       verifyingOwner: true)) else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        proof.recoveryService = service
        guard proof.matchesRoute(), try proof.matchesCurrent(),
              let move = DirectoryMove(from: source, to: stage, owner: proof.owner)
        else { throw Failure(errorDescription: L.t("error.cliProfile")) }
        proof.directoryMove = move

        var template = Array(root.appendingPathComponent(".retirement-XXXXXX").path.utf8CString)
        let descriptor = mkstemp(&template)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let prepared = URL(fileURLWithPath: String(cString: template))
        defer { _ = unlink(prepared.path) }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        try file.write(contentsOf: Data((proof.selection + "\n").utf8))
        try writeProof(proof, descriptor: descriptor)
        let receipt = root.appendingPathComponent(parkedPrefix + UUID().uuidString)
        try moveSelection(from: prepared, to: receipt)
        return (receipt, move.fallbackFile)
    }

    private static func moveSelection(from source: URL, to destination: URL) throws {
        guard renameatx_np(AT_FDCWD, source.path, AT_FDCWD, destination.path, UInt32(RENAME_EXCL)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    static func stage(_ account: DiscoveredAccount) throws -> Prepared {
        guard case .claudeKeychain(let service, _) = account.source else {
            throw Failure(errorDescription: L.t("error.unknownSource"))
        }
        let selection: String
        if service == AuthStorage$Claude.baseService {
            selection = ""
        } else if let path = AuthStorage$Claude.configPath(for: service) {
            selection = path
        } else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        guard !selection.contains("\n"), !selection.contains("\r") else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        guard (service == AuthStorage$Claude.baseService
                ? AuthStorage$Claude.matchesPrimaryOwner(account)
                : account.claudeConfigOwner?.matches(URL(fileURLWithPath: selection)) == true) else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        let home = ProfileDirectories.home
        let shell = URL(fileURLWithPath: ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh").lastPathComponent
        let startups: [URL]
        switch shell {
        case "zsh":
            let interactive = try zshStartupDirectory(home: home, login: false)
            let login = try zshStartupDirectory(home: home, login: true)
            startups = (interactive == login ? [interactive] : [interactive, login]).map {
                $0.appendingPathComponent(".zshrc")
            }
        case "bash":
            let candidates = [".bash_profile", ".bash_login", ".profile"].map { home.appendingPathComponent($0) }
            let login = candidates.first { FileManager.default.fileExists(atPath: $0.path) } ?? candidates[0]
            startups = [login, home.appendingPathComponent(".bashrc")]
        default: throw Failure(errorDescription: L.t("error.cliShell"))
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let script = root.appendingPathComponent("profile.sh")
        let wasIntegrated = FileManager.default.fileExists(atPath: script.path)
        if !wasIntegrated && !FileManager.default.fileExists(atPath: pointer.path) {
            // Installing the function must preserve default CLI routing until commit.
            try Data("\n".utf8).write(to: pointer, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pointer.path)
        }
        let content = """
        # Managed by Notchlimits. No credentials are stored in this file.
        function claude {
            if [ "${CLAUDE_CONFIG_DIR+x}" = x ] || [ "${CLAUDE_SECURESTORAGE_CONFIG_DIR+x}" = x ]; then
                command claude "$@"
                return $?
            fi
            local notchlimits_profile
            if ! IFS= read -r notchlimits_profile < \(quote(pointer.path)); then
                printf '%s\\n' 'Notchlimits: cannot read the selected Claude profile.' >&2
                return 1
            fi
            if [ -z "$notchlimits_profile" ]; then
                (unset CLAUDE_CONFIG_DIR; command claude "$@")
            elif [ "${notchlimits_profile#/}" != "$notchlimits_profile" ] && [ -d "$notchlimits_profile" ]; then
                CLAUDE_CONFIG_DIR="$notchlimits_profile" command claude "$@"
            else
                printf '%s\\n' 'Notchlimits: the selected Claude profile is unavailable.' >&2
                return 1
            fi
        }
        """
        try Data((content + "\n").utf8).write(to: script, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: script.path)
        let source = ". \(quote(script.path))"
        for startup in startups {
            let existing = (try? String(contentsOf: startup, encoding: .utf8)) ?? ""
            if existing.components(separatedBy: .newlines).contains(source) { continue }
            if !FileManager.default.fileExists(atPath: startup.path) {
                FileManager.default.createFile(atPath: startup.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            let handle = try FileHandle(forWritingTo: startup)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: Data(("\n# Notchlimits Claude profile selection\n" + source + "\n").utf8))
        }
        let staged = root.appendingPathComponent(".selected-profile-" + UUID().uuidString)
        do {
            try Data((selection + "\n").utf8).write(to: staged, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staged.path)
        } catch {
            try? FileManager.default.removeItem(at: staged)
            throw error
        }
        return Prepared(staged: staged, pointer: pointer, service: service, selection: selection, account: account)
    }

    final class Prepared {
        private let staged: URL
        private let pointer: URL
        private let service: String
        private let selection: String
        private let account: DiscoveredAccount
        private var committed = false

        fileprivate init(staged: URL, pointer: URL, service: String, selection: String, account: DiscoveredAccount) {
            self.staged = staged
            self.pointer = pointer
            self.service = service
            self.selection = selection
            self.account = account
        }

        func commit(revisionIsCurrent: (() -> Bool)?) throws {
            func ownsProfile() -> Bool {
                (service == AuthStorage$Claude.baseService
                    ? AuthStorage$Claude.matchesPrimaryOwner(account)
                    : AuthStorage$Claude.configPath(for: service) == selection
                        && account.claudeConfigOwner?.matches(URL(fileURLWithPath: selection)) == true)
                    && AuthStorage$Claude.contains(service: service)
            }
            guard try CLISelection$Claude.withSelectionLock({
                guard ownsProfile(), revisionIsCurrent?() == true
                        || AuthStorage$Claude.validateSelectionLogin(service: service, ownsProfile: ownsProfile) else {
                    throw Failure(errorDescription: L.t("error.cliProfile"))
                }
                guard rename(staged.path, pointer.path) == 0 else {
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
                }
                try? CLISelection$Claude.parkSupersededRetirement()
                return true
            }) == true else { throw Failure(errorDescription: L.t("error.cliProfile")) }
            committed = true
        }

        deinit {
            if !committed { try? FileManager.default.removeItem(at: staged) }
        }
    }

    private static func zshStartupDirectory(home: URL, login: Bool) throws -> URL {
        let probeDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("notchlimits-zsh-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: probeDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: probeDirectory) }
        let output = probeDirectory.appendingPathComponent("dotdir")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        // Resolve the .zshrc location without running the .zshrc itself.
        process.arguments = [login ? "-fil" : "-fi", "-c", #"""
            setopt rcs
            if [[ -r "${ZDOTDIR-$HOME}/.zshenv" ]]; then
                builtin source "${ZDOTDIR-$HOME}/.zshenv"
            fi
            if [[ -o login ]]; then
                if [[ -o rcs && -o globalrcs && -r /etc/zprofile ]]; then
                    builtin source /etc/zprofile
                fi
                if [[ -o rcs && -r "${ZDOTDIR-$HOME}/.zprofile" ]]; then
                    builtin source "${ZDOTDIR-$HOME}/.zprofile"
                fi
            fi
            unsetopt rcs
            builtin print -rn -- "${ZDOTDIR-$HOME}" >| "$1"
            """#, "notchlimits", output.path]
        var environment = ProcessInfo.processInfo.environment
        environment["HOME"] = home.path
        process.environment = environment
        process.currentDirectoryURL = home
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        try process.run()
        guard exited.wait(timeout: .now() + 2) == .success else {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            throw Failure(errorDescription: L.t("error.cliShell"))
        }
        guard process.terminationStatus == 0,
              let path = try? String(contentsOf: output, encoding: .utf8),
              path.hasPrefix("/") else { throw Failure(errorDescription: L.t("error.cliShell")) }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    private static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
