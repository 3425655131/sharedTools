import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var viewModel = AppViewModel()

    var body: some View {
        VStack(spacing: 10) {
            fileRow
            resultPanel
            progressAndShellSection
        }
        .padding(18)
        .background(Color(nsColor: NSColor(calibratedWhite: 0.93, alpha: 1.0)))
        .frame(width: 760, height: 420)
    }

    private var fileRow: some View {
        HStack(spacing: 8) {
            Text("File")
                .font(.system(size: 14, weight: .semibold))
                .frame(width: 40, alignment: .leading)

            TextField("选择 APK 文件", text: $viewModel.selectedPath)
                .textFieldStyle(.plain)
                .padding(.horizontal, 8)
                .frame(height: 26)
                .background(Color.white)
                .overlay(Rectangle().stroke(Color(nsColor: .gridColor), lineWidth: 1))
                .disabled(viewModel.isAnalyzing)

            Button("...") {
                viewModel.pickAPK()
            }
            .frame(width: 44)
            .disabled(viewModel.isAnalyzing)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 10)
        .background(Color.white)
        .overlay(Rectangle().stroke(Color(nsColor: .gridColor), lineWidth: 1))
    }

    private var resultPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let result = viewModel.result {
                Text("查壳结论：\(result.detection.verdict)")
                    .font(.system(size: 17, weight: .bold))
                Text("置信度：\(result.detection.confidence)")
                    .font(.system(size: 13))
                infoLine("判定说明", result.detection.rationale)
                Divider()
                infoLine("包名", result.metadata.packageName)
                infoLine("版本", "\(result.metadata.versionName) (\(result.metadata.versionCode))")
                infoLine("SDK", "\(result.metadata.minSDK) / \(result.metadata.targetSDK)")
                infoLine("ABI", result.metadata.abiSummary)
                infoLine("证书", result.metadata.certificateSummary)
                infoLine("命中特征", result.detection.matchedFeatures.isEmpty ? "无" : result.detection.matchedFeatures.joined(separator: "、"))
                infoLine("耗时", "\(result.elapsedMilliseconds) ms")
            } else if let errorText = viewModel.errorText {
                Text("分析失败")
                    .font(.system(size: 17, weight: .bold))
                Text(errorText)
                    .foregroundStyle(.red)
                Divider()
                Text(viewModel.summaryText)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text(viewModel.summaryText)
                    .font(.system(size: 13))
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Text("拖放文件至窗口即可开始解析！")
                    .font(.system(size: 13, weight: .semibold))
                    .frame(maxWidth: .infinity, alignment: .center)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color.white)
        .overlay(
            Rectangle()
                .stroke(viewModel.isDropTargeted ? Color.accentColor : Color(nsColor: .gridColor), lineWidth: viewModel.isDropTargeted ? 2 : 1)
        )
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: $viewModel.isDropTargeted) { providers in
            viewModel.handleProviders(providers)
        }
    }

    private var progressAndShellSection: some View {
        VStack(spacing: 8) {
            HStack {
                Text(viewModel.progressLabel.isEmpty ? "等待开始解析" : viewModel.progressLabel)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Spacer()
                if viewModel.result != nil {
                    Button("复制结果") {
                        viewModel.copySummaryToPasteboard()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }

            ProgressView(value: viewModel.progressValue)
                .progressViewStyle(.linear)

            HStack(spacing: 8) {
                Text("Shell")
                    .font(.system(size: 14, weight: .semibold))
                    .frame(width: 40, alignment: .leading)

                TextField("", text: .constant(viewModel.shellSummary))
                    .textFieldStyle(.plain)
                    .padding(.horizontal, 8)
                    .frame(height: 26)
                    .background(Color.white)
                    .overlay(Rectangle().stroke(Color(nsColor: .gridColor), lineWidth: 1))
                    .disabled(true)

                Button("Exit") {
                    NSApp.terminate(nil)
                }
                .frame(width: 56)
            }
        }
    }

    private func infoLine(_ title: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text("\(title)：")
                .font(.system(size: 13, weight: .semibold))
                .frame(width: 58, alignment: .leading)
            Text(value)
                .font(.system(size: 13))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }
}
