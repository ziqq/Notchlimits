private enum CodexFileMutation {
    static var beforeTransfer: ((URL) throws -> Void)?
    static var afterTransfer: ((URL, URL) -> Void)?
}

private func stageCodexAuth(_ sourceFD: Int32, _ source: UnsafePointer<CChar>,
                            _ destinationFD: Int32, _ destination: UnsafePointer<CChar>, _ flags: UInt32) -> Int32? {
    guard let files = codexStagedAuthFiles(sourceFD, source, destinationFD, destination) else { return nil }
    if credentialRemovalDenied(files.source) {
        errno = EACCES
        return -1
    }
    do { try CodexFileMutation.beforeTransfer?(files.source) }
    catch {
        errno = EACCES
        return -1
    }
    let result = Darwin.renameatx_np(sourceFD, source, destinationFD, destination, flags)
    if result == 0 { CodexFileMutation.afterTransfer?(files.source, files.destination) }
    return result
}
