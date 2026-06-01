import Foundation

public struct APKMetadata: Sendable, Equatable {
    public let fileName: String
    public let packageName: String
    public let versionName: String
    public let versionCode: String
    public let minSDK: String
    public let targetSDK: String
    public let abiSummary: String
    public let certificateSummary: String

    public init(
        fileName: String,
        packageName: String,
        versionName: String,
        versionCode: String,
        minSDK: String,
        targetSDK: String,
        abiSummary: String,
        certificateSummary: String
    ) {
        self.fileName = fileName
        self.packageName = packageName
        self.versionName = versionName
        self.versionCode = versionCode
        self.minSDK = minSDK
        self.targetSDK = targetSDK
        self.abiSummary = abiSummary
        self.certificateSummary = certificateSummary
    }

    public static func empty(fileName: String) -> APKMetadata {
        APKMetadata(
            fileName: fileName,
            packageName: "不可用",
            versionName: "不可用",
            versionCode: "不可用",
            minSDK: "不可用",
            targetSDK: "不可用",
            abiSummary: "不可用",
            certificateSummary: "不可用"
        )
    }
}

public enum AnalysisStage: Int, CaseIterable, Sendable {
    case validating = 1
    case readingManifest
    case extractingMetadata
    case matchingShell
    case finalizing

    public var progressLabel: String {
        switch self {
        case .validating:
            return "正在校验 APK 文件（第 1/5 步）"
        case .readingManifest:
            return "正在读取 AndroidManifest.xml（第 2/5 步）"
        case .extractingMetadata:
            return "正在提取基础信息（第 3/5 步）"
        case .matchingShell:
            return "正在匹配加固规则（第 4/5 步）"
        case .finalizing:
            return "正在整理结果（第 5/5 步）"
        }
    }

    public var fractionCompleted: Double {
        Double(rawValue) / Double(Self.allCases.count)
    }
}

public struct AnalysisProgress: Sendable, Equatable {
    public let stage: AnalysisStage
    public let label: String
    public let fractionCompleted: Double

    public init(stage: AnalysisStage) {
        self.stage = stage
        self.label = stage.progressLabel
        self.fractionCompleted = stage.fractionCompleted
    }
}

public enum ShellDetectionDisposition: String, Sendable, Equatable {
    case detectedKnown
    case suspectedFamily
    case suspectedUnknown
    case unknown
}

public struct ShellDetectionResult: Sendable, Equatable {
    public let vendor: String
    public let matchedFeatures: [String]
    public let confidence: String
    public let verdict: String
    public let rationale: String
    public let disposition: ShellDetectionDisposition

    public init(
        vendor: String,
        matchedFeatures: [String],
        confidence: String,
        verdict: String,
        rationale: String,
        disposition: ShellDetectionDisposition
    ) {
        self.vendor = vendor
        self.matchedFeatures = matchedFeatures
        self.confidence = confidence
        self.verdict = verdict
        self.rationale = rationale
        self.disposition = disposition
    }
}

public struct APKAnalysisResult: Sendable, Equatable {
    public let metadata: APKMetadata
    public let detection: ShellDetectionResult
    public let archiveEntries: [String]
    public let elapsedMilliseconds: Int

    public init(
        metadata: APKMetadata,
        detection: ShellDetectionResult,
        archiveEntries: [String],
        elapsedMilliseconds: Int
    ) {
        self.metadata = metadata
        self.detection = detection
        self.archiveEntries = archiveEntries
        self.elapsedMilliseconds = elapsedMilliseconds
    }
}

public extension APKAnalysisResult {
    static func preview(vendor: String) -> APKAnalysisResult {
        APKAnalysisResult(
            metadata: APKMetadata(
                fileName: "demo.apk",
                packageName: "com.demo.shell",
                versionName: "1.0.0",
                versionCode: "1",
                minSDK: "24",
                targetSDK: "34",
                abiSummary: "arm64-v8a, armeabi-v7a",
                certificateSummary: "CN=Preview, SHA256=DE:MO"
            ),
            detection: ShellDetectionResult(
                vendor: vendor,
                matchedFeatures: vendor == "未识别到已知加固" ? [] : ["libsecexe.so"],
                confidence: vendor == "未识别到已知加固" ? "未命中内置规则" : "高",
                verdict: vendor,
                rationale: vendor == "未识别到已知加固" ? "未命中已知家族特征或通用可疑壳簇。" : "命中高置信家族特征。",
                disposition: vendor == "未识别到已知加固" ? .unknown : .detectedKnown
            ),
            archiveEntries: ["AndroidManifest.xml", "classes.dex"],
            elapsedMilliseconds: 321
        )
    }
}

public enum APKAnalysisError: LocalizedError {
    case invalidFileExtension
    case unreadableArchive
    case manifestMissing
    case commandFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidFileExtension:
            return "请选择有效的 APK 文件。"
        case .unreadableArchive:
            return "APK 文件无法读取，可能已损坏。"
        case .manifestMissing:
            return "APK 中未找到 AndroidManifest.xml。"
        case .commandFailed(let message):
            return message
        }
    }
}
