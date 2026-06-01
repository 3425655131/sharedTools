import Foundation

public actor APKAnalyzer {
    private let archiveReader: ArchiveReading
    private let manifestParser: BinaryAndroidManifestParsing
    private let certificateExtractor: CertificateExtracting
    private let detector: ShellDetector
    private let stubbedResult: APKAnalysisResult?
    private let stubbedError: APKAnalysisError?
    private let stubbedStages: [AnalysisStage]?

    public init(
        archiveReader: ArchiveReading = ArchiveReader(),
        manifestParser: BinaryAndroidManifestParsing = BinaryAndroidManifestParser(),
        certificateExtractor: CertificateExtracting = CertificateExtractor(),
        detector: ShellDetector = .default,
        stubbedResult: APKAnalysisResult? = nil,
        stubbedError: APKAnalysisError? = nil,
        stubbedStages: [AnalysisStage]? = nil
    ) {
        self.archiveReader = archiveReader
        self.manifestParser = manifestParser
        self.certificateExtractor = certificateExtractor
        self.detector = detector
        self.stubbedResult = stubbedResult
        self.stubbedError = stubbedError
        self.stubbedStages = stubbedStages
    }

    public static func stubbed(
        result: APKAnalysisResult? = nil,
        error: APKAnalysisError? = nil,
        progressStages: [AnalysisStage]
    ) -> APKAnalyzer {
        APKAnalyzer(
            stubbedResult: result,
            stubbedError: error,
            stubbedStages: progressStages
        )
    }

    public static var previewSucceeded: APKAnalyzer {
        .stubbed(
            result: .preview(vendor: "未识别到已知加固"),
            progressStages: [.validating]
        )
    }

    public func analyze(
        apkURL: URL,
        progress: (@Sendable (AnalysisProgress) async -> Void)? = nil
    ) async throws -> APKAnalysisResult {
        if let stubbedStages {
            for stage in stubbedStages {
                await emit(stage: stage, progress: progress)
            }
            if let stubbedError {
                throw stubbedError
            }
            if let stubbedResult {
                return stubbedResult
            }
        }

        await emit(stage: .validating, progress: progress)
        guard apkURL.pathExtension.lowercased() == "apk" else {
            throw APKAnalysisError.invalidFileExtension
        }

        let startedAt = Date()
        let entries = try archiveReader.listEntries(in: apkURL)
        guard !entries.isEmpty else {
            throw APKAnalysisError.unreadableArchive
        }

        await emit(stage: .readingManifest, progress: progress)
        guard entries.contains("AndroidManifest.xml") else {
            throw APKAnalysisError.manifestMissing
        }

        let manifestData = try archiveReader.readEntry(named: "AndroidManifest.xml", from: apkURL)
        await emit(stage: .extractingMetadata, progress: progress)
        var metadata = try manifestParser.parse(data: manifestData, fileName: apkURL.lastPathComponent)
        let abiSummary = summarizeABIs(from: entries)
        let certificateSummary = (try? certificateExtractor.extractSummary(from: apkURL, entries: entries, archiveReader: archiveReader)) ?? "不可用"

        metadata = APKMetadata(
            fileName: metadata.fileName,
            packageName: metadata.packageName,
            versionName: metadata.versionName,
            versionCode: metadata.versionCode,
            minSDK: metadata.minSDK,
            targetSDK: metadata.targetSDK,
            abiSummary: abiSummary,
            certificateSummary: certificateSummary
        )

        await emit(stage: .matchingShell, progress: progress)
        let detection = detector.detect(from: entries)
        await emit(stage: .finalizing, progress: progress)
        let elapsedMilliseconds = Int(Date().timeIntervalSince(startedAt) * 1000)
        return APKAnalysisResult(
            metadata: metadata,
            detection: detection,
            archiveEntries: entries,
            elapsedMilliseconds: elapsedMilliseconds
        )
    }

    public nonisolated func makeCopySummary(for result: APKAnalysisResult) -> String {
        [
            "文件名: \(result.metadata.fileName)",
            "查壳结论: \(result.detection.verdict)",
            "判定说明: \(result.detection.rationale)",
            "命中特征: \(result.detection.matchedFeatures.isEmpty ? "无" : result.detection.matchedFeatures.joined(separator: ", "))",
            "包名: \(result.metadata.packageName)",
            "版本名: \(result.metadata.versionName)",
            "版本号: \(result.metadata.versionCode)",
            "最低 SDK: \(result.metadata.minSDK)",
            "目标 SDK: \(result.metadata.targetSDK)",
            "ABI: \(result.metadata.abiSummary)",
            "证书摘要: \(result.metadata.certificateSummary)",
            "耗时: \(result.elapsedMilliseconds) ms",
        ].joined(separator: "\n")
    }

    private func summarizeABIs(from entries: [String]) -> String {
        let prefixes = entries.compactMap { entry -> String? in
            guard entry.hasPrefix("lib/") else { return nil }
            let components = entry.split(separator: "/")
            guard components.count >= 3 else { return nil }
            return String(components[1])
        }

        let unique = Array(Set(prefixes)).sorted()
        return unique.isEmpty ? "不可用" : unique.joined(separator: ", ")
    }

    private func emit(
        stage: AnalysisStage,
        progress: (@Sendable (AnalysisProgress) async -> Void)?
    ) async {
        guard let progress else { return }
        await progress(AnalysisProgress(stage: stage))
    }
}
