import AppKit
import Foundation
import UniformTypeIdentifiers
import APKShellInspectorCore

@MainActor
final class AppViewModel: ObservableObject {
    @Published var selectedPath = ""
    @Published var statusText = "拖入 APK 或点“选择文件”开始分析。"
    @Published var isAnalyzing = false
    @Published var isDropTargeted = false
    @Published var progressLabel = ""
    @Published var progressValue = 0.0
    @Published var shellSummary = "此 APK 未采用加固或尚未开始解析。"
    @Published var result: APKAnalysisResult?
    @Published var errorText: String?

    private let analyzer: APKAnalyzer

    init(analyzer: APKAnalyzer = APKAnalyzer()) {
        self.analyzer = analyzer
    }

    var summaryText: String {
        if let result {
            return analyzer.makeCopySummary(for: result)
        }

        return """
        当前支持常见加固家族识别，并会对疑似壳簇给出偏向判断与可疑提示。

        本工具纯本地离线运行，不上传 APK。
        可直接拖拽 APK 到窗口，也可使用上方文件选择按钮导入。
        """
    }

    func pickAPK() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "apk")].compactMap { $0 }

        if panel.runModal() == .OK, let url = panel.url {
            Task {
                await load(url: url)
            }
        }
    }

    func handleProviders(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else {
            return false
        }

        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
            guard let data = item as? Data,
                  let url = URL(dataRepresentation: data, relativeTo: nil) else {
                return
            }

            Task { @MainActor in
                await self.load(url: url)
            }
        }

        return true
    }

    func load(url: URL) async {
        selectedPath = url.path
        beginProgressPreview()
        statusText = "正在分析 \(url.lastPathComponent)..."
        isAnalyzing = true
        errorText = nil
        result = nil

        do {
            let analyzed = try await analyzer.analyze(apkURL: url) { [weak self] progress in
                await MainActor.run {
                    self?.progressLabel = progress.label
                    self?.progressValue = progress.fractionCompleted
                    self?.shellSummary = "正在分析..."
                }
            }
            result = analyzed
            progressLabel = "解析完成"
            progressValue = 1.0
            shellSummary = analyzed.detection.verdict
            statusText = statusText(for: analyzed.detection)
        } catch {
            errorText = error.localizedDescription
            let failureSummary = failureSummaryText(for: error)
            progressLabel = "解析失败：\(failureSummary)"
            shellSummary = "解析失败"
            statusText = "解析失败：\(failureSummary)"
        }

        isAnalyzing = false
    }

    func beginProgressPreview() {
        let initialProgress = AnalysisProgress(stage: .validating)
        progressLabel = initialProgress.label
        progressValue = initialProgress.fractionCompleted
        shellSummary = "正在分析..."
    }

    func copySummaryToPasteboard() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(summaryText, forType: .string)
        statusText = "结果已复制到剪贴板。"
    }

    private func failureSummaryText(for error: Error) -> String {
        if let analysisError = error as? APKAnalysisError {
            switch analysisError {
            case .manifestMissing:
                return "未找到 AndroidManifest.xml"
            case .invalidFileExtension:
                return "请选择有效的 APK 文件"
            case .unreadableArchive:
                return "APK 文件损坏或无法读取"
            case .commandFailed(let message):
                return message.trimmingCharacters(in: CharacterSet(charactersIn: "。"))
            }
        }

        return error.localizedDescription.trimmingCharacters(in: CharacterSet(charactersIn: "。"))
    }

    private func statusText(for detection: ShellDetectionResult) -> String {
        switch detection.disposition {
        case .detectedKnown:
            return "分析完成，检测到 \(detection.vendor)。"
        case .suspectedFamily:
            return "分析完成，\(detection.verdict)。"
        case .suspectedUnknown:
            return "分析完成，检测到通用可疑壳簇。"
        case .unknown:
            return "分析完成，未检测到已知加固。"
        }
    }
}
