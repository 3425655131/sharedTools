import Foundation
import Testing
@testable import APKShellInspectorCore

@Test("进程读取器能消费大体积标准输出而不卡死")
func processRunnerConsumesLargeStdout() throws {
    let data = try runCommandDataStreaming(
        executable: "/usr/bin/python3",
        arguments: ["-c", "import sys; sys.stdout.write('x' * 200000)"]
    )

    #expect(data.count == 200000)
}
