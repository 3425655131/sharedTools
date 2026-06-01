import Foundation
import Testing
@testable import APKShellInspectorApp
@testable import APKShellInspectorCore

@MainActor
@Test("视图模型按中文步骤推进解析进度")
func progressStagesAdvanceInChinese() async throws {
    let analyzer = APKAnalyzer.stubbed(
        result: .preview(vendor: "梆梆加固"),
        progressStages: [.validating, .readingManifest, .extractingMetadata, .matchingShell, .finalizing]
    )
    let viewModel = AppViewModel(analyzer: analyzer)

    await viewModel.load(url: URL(fileURLWithPath: "/tmp/demo.apk"))

    #expect(viewModel.progressLabel == "解析完成")
    #expect(viewModel.progressValue == 1.0)
    #expect(viewModel.shellSummary.contains("梆梆加固"))
}

@MainActor
@Test("分析失败时保留失败步骤与进度")
func progressStageStopsOnFailure() async throws {
    let analyzer = APKAnalyzer.stubbed(
        error: APKAnalysisError.manifestMissing,
        progressStages: [.validating, .readingManifest]
    )
    let viewModel = AppViewModel(analyzer: analyzer)

    await viewModel.load(url: URL(fileURLWithPath: "/tmp/bad.apk"))

    #expect(viewModel.progressLabel == "解析失败：未找到 AndroidManifest.xml")
    #expect(viewModel.progressValue == 0.4)
}

@MainActor
@Test("分析中时 Shell 文案切到进行态")
func shellSummaryShowsAnalyzingState() {
    let viewModel = AppViewModel(analyzer: .previewSucceeded)

    viewModel.beginProgressPreview()

    #expect(viewModel.shellSummary == "正在分析...")
    #expect(viewModel.progressLabel.contains("第 1/5 步"))
}

@MainActor
@Test("疑似家族结论会展示偏向文案")
func suspectedFamilyVerdictShownInShellSummary() async throws {
    let result = APKAnalysisResult(
        metadata: APKMetadata(
            fileName: "sample.apk",
            packageName: "com.demo.sample",
            versionName: "1.0.0",
            versionCode: "1",
            minSDK: "24",
            targetSDK: "34",
            abiSummary: "arm64-v8a",
            certificateSummary: "CN=Demo"
        ),
        detection: ShellDetectionResult(
            vendor: "娜迦加固",
            matchedFeatures: ["assets/meta-data/manifest.mf", "libjade2"],
            confidence: "中",
            verdict: "疑似加固（偏向娜迦加固）",
            rationale: "命中部分家族特征，但不足以直接确认厂商。",
            disposition: .suspectedFamily
        ),
        archiveEntries: ["AndroidManifest.xml"],
        elapsedMilliseconds: 88
    )
    let analyzer = APKAnalyzer.stubbed(result: result, progressStages: [.validating])
    let viewModel = AppViewModel(analyzer: analyzer)

    await viewModel.load(url: URL(fileURLWithPath: "/tmp/demo.apk"))

    #expect(viewModel.shellSummary == "疑似加固（偏向娜迦加固）")
    #expect(viewModel.statusText.contains("疑似"))
}
