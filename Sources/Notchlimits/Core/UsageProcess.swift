import Darwin
import Foundation

/// A foreground CLI owned by a single usage request. Never log its output.
final class UsageProcess {
    enum Failure: Error { case timeout, closed, invalidOutput }

    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let exited = DispatchSemaphore(value: 0)
    private let directory: URL
    private var pending = Data()

    init(binary: URL, arguments: [String], environment: [String: String]) throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("notchlimits-usage-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        process.executableURL = binary
        process.arguments = arguments
        process.environment = environment
        process.currentDirectoryURL = directory
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [exited] _ in exited.signal() }
        _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
        do {
            try process.run()
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    deinit {
        try? input.fileHandleForWriting.close()
        if process.isRunning {
            process.terminate()
            if exited.wait(timeout: .now() + 1) == .timedOut, process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                process.waitUntilExit()
            }
        }
        try? FileManager.default.removeItem(at: directory)
    }

    func send(_ message: [String: Any]) throws {
        var data = try JSONSerialization.data(withJSONObject: message)
        data.append(10)
        try input.fileHandleForWriting.write(contentsOf: data)
    }

    func line(until deadline: DispatchTime) throws -> Data {
        let fd = output.fileHandleForReading.fileDescriptor
        while DispatchTime.now() < deadline {
            if let newline = pending.firstIndex(of: 10) {
                let line = Data(pending[..<newline])
                pending.removeSubrange(...newline)
                return line
            }
            guard pending.count < 1_048_576 else { throw Failure.invalidOutput }
            let remaining = deadline.uptimeNanoseconds - min(deadline.uptimeNanoseconds,
                                                             DispatchTime.now().uptimeNanoseconds)
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let result = poll(&descriptor, 1, Int32((remaining + 999_999) / 1_000_000))
            if result == 0 { throw Failure.timeout }
            if result < 0, errno == EINTR { continue }
            guard result > 0 else { throw Failure.closed }
            let data = output.fileHandleForReading.availableData
            guard !data.isEmpty else { throw Failure.closed }
            pending.append(data)
        }
        throw Failure.timeout
    }
}
