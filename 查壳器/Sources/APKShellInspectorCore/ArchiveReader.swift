import Foundation

public protocol ArchiveReading: Sendable {
    func listEntries(in apkURL: URL) throws -> [String]
    func readEntry(named entryName: String, from apkURL: URL) throws -> Data
}

public struct ArchiveReader: ArchiveReading {
    public init() {}

    public func listEntries(in apkURL: URL) throws -> [String] {
        let output = try runCommand(
            executable: "/usr/bin/unzip",
            arguments: ["-Z1", apkURL.path]
        )
        return output
            .split(separator: "\n")
            .map(String.init)
            .filter { !$0.isEmpty }
    }

    public func readEntry(named entryName: String, from apkURL: URL) throws -> Data {
        try runCommandData(
            executable: "/usr/bin/unzip",
            arguments: ["-p", apkURL.path, entryName]
        )
    }
}

@discardableResult
func runCommand(
    executable: String,
    arguments: [String],
    input: Data? = nil
) throws -> String {
    let data = try runCommandDataStreaming(executable: executable, arguments: arguments, input: input)
    return String(decoding: data, as: UTF8.self)
}

func runCommandData(
    executable: String,
    arguments: [String],
    input: Data? = nil
) throws -> Data {
    try runCommandDataStreaming(executable: executable, arguments: arguments, input: input)
}

func runCommandDataStreaming(
    executable: String,
    arguments: [String],
    input: Data? = nil
) throws -> Data {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments

    let outputPipe = Pipe()
    let errorPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = errorPipe

    let stdoutReader = PipeCollector(handle: outputPipe.fileHandleForReading)
    let stderrReader = PipeCollector(handle: errorPipe.fileHandleForReading)
    stdoutReader.start()
    stderrReader.start()

    if let input {
        let inputPipe = Pipe()
        process.standardInput = inputPipe
        try process.run()
        inputPipe.fileHandleForWriting.write(input)
        inputPipe.fileHandleForWriting.closeFile()
    } else {
        try process.run()
    }

    process.waitUntilExit()
    let output = try stdoutReader.finish()
    let error = try stderrReader.finish()

    guard process.terminationStatus == 0 else {
        let message = String(decoding: error, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        throw APKAnalysisError.commandFailed(message.isEmpty ? "本地分析命令执行失败。" : message)
    }

    return output
}

private final class PipeCollector: @unchecked Sendable {
    private let handle: FileHandle
    private let group = DispatchGroup()
    private let queue = DispatchQueue(label: "APKShellInspector.PipeCollector", qos: .userInitiated)

    private var collectedData = Data()
    private var readError: Error?

    init(handle: FileHandle) {
        self.handle = handle
    }

    func start() {
        group.enter()
        queue.async { [weak self] in
            defer { self?.group.leave() }
            guard let self else { return }

            do {
                self.collectedData = try self.handle.readToEnd() ?? Data()
            } catch {
                self.readError = error
            }
        }
    }

    func finish() throws -> Data {
        group.wait()
        if let readError {
            throw readError
        }
        return collectedData
    }
}
