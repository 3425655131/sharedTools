# Mac APK Shell Inspector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a distributable macOS native app that opens APK files, extracts basic metadata, detects common shell vendors offline, and packages as a double-clickable `.app`.

**Architecture:** Use a Swift Package with one reusable core library and one SwiftUI app executable. The core library handles ZIP access, binary AndroidManifest parsing, certificate fingerprint extraction, and shell-rule matching. The app target owns drag-and-drop, file picking, status updates, and result rendering. A shell script turns the release binary into a macOS `.app` bundle without requiring Xcode.app.

**Tech Stack:** Swift 6, SwiftUI, Foundation, Swift Testing, macOS system tools (`unzip`, `openssl`), custom `.app` bundling script

---

### Task 1: Scaffold the Package and Build Script

**Files:**
- Create: `Package.swift`
- Create: `Sources/APKShellInspectorApp/APKShellInspectorApp.swift`
- Create: `Sources/APKShellInspectorCore/Placeholder.swift`
- Create: `Tests/APKShellInspectorCoreTests/SmokeTests.swift`
- Create: `scripts/build-app.sh`

- [ ] **Step 1: Write the failing package smoke test**

```swift
import Testing
@testable import APKShellInspectorCore

@Test("package boots with a stable placeholder")
func placeholderIsStable() {
    #expect(Placeholder.value == "pending")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test`
Expected: FAIL with `no such module 'APKShellInspectorCore'` or missing `Placeholder`

- [ ] **Step 3: Write the minimal package skeleton**

```swift
// Package.swift
// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "APKShellInspector",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "APKShellInspectorCore", targets: ["APKShellInspectorCore"]),
        .executable(name: "APKShellInspector", targets: ["APKShellInspectorApp"]),
    ],
    targets: [
        .target(name: "APKShellInspectorCore"),
        .executableTarget(
            name: "APKShellInspectorApp",
            dependencies: ["APKShellInspectorCore"]
        ),
        .testTarget(
            name: "APKShellInspectorCoreTests",
            dependencies: ["APKShellInspectorCore"]
        ),
    ]
)
```

```swift
// Sources/APKShellInspectorCore/Placeholder.swift
public enum Placeholder {
    public static let value = "pending"
}
```

```swift
// Sources/APKShellInspectorApp/APKShellInspectorApp.swift
import SwiftUI

@main
struct APKShellInspectorApp: App {
    var body: some Scene {
        WindowGroup {
            Text("APK Shell Inspector")
                .frame(width: 760, height: 460)
        }
        .windowResizability(.contentSize)
    }
}
```

```bash
#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/.build/release"
APP_DIR="$ROOT_DIR/dist/APKShellInspector.app"
BIN_PATH="$BUILD_DIR/APKShellInspector"

swift build -c release --product APKShellInspector
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BIN_PATH" "$APP_DIR/Contents/MacOS/APKShellInspector"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `swift test`
Expected: PASS with `package boots with a stable placeholder`

- [ ] **Step 5: Commit**

```bash
git add Package.swift Sources Tests scripts
git commit -m "feat: scaffold mac apk shell inspector package"
```

### Task 2: Implement ZIP Reading and Shell Detection

**Files:**
- Create: `Sources/APKShellInspectorCore/Models/APKAnalysis.swift`
- Create: `Sources/APKShellInspectorCore/Services/ArchiveReader.swift`
- Create: `Sources/APKShellInspectorCore/Services/ShellRule.swift`
- Create: `Sources/APKShellInspectorCore/Services/ShellDetector.swift`
- Create: `Tests/APKShellInspectorCoreTests/ShellDetectorTests.swift`

- [ ] **Step 1: Write the failing shell detector tests**

```swift
import Foundation
import Testing
@testable import APKShellInspectorCore

@Test("detects Bangcle from well-known entry names")
func detectsBangcle() throws {
    let detector = ShellDetector.default
    let entries = [
        "assets/bangcleplugin/container.dex",
        "lib/armeabi-v7a/libsecexe.so",
    ]

    let result = detector.detect(from: entries)

    #expect(result.vendor == "梆梆加固")
    #expect(result.matchedFeatures.count == 2)
}

@Test("returns unknown when no shell signature matches")
func detectsUnknown() {
    let detector = ShellDetector.default

    let result = detector.detect(from: ["classes.dex", "AndroidManifest.xml"])

    #expect(result.vendor == "未识别到已知加固")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test --filter ShellDetectorTests`
Expected: FAIL with missing `ShellDetector`

- [ ] **Step 3: Write the minimal detector implementation**

```swift
public struct ShellDetectionResult: Sendable {
    public let vendor: String
    public let matchedFeatures: [String]
}

public struct ShellRule: Sendable {
    public let vendor: String
    public let requiredPatterns: [String]
}

public struct ShellDetector: Sendable {
    public static let `default` = ShellDetector(rules: [
        .init(vendor: "梆梆加固", requiredPatterns: ["assets/bangcle", "libsecexe.so"]),
        .init(vendor: "360加固", requiredPatterns: ["libjiagu.so"]),
        .init(vendor: "爱加密", requiredPatterns: ["ijiami", "libexecmain.so"]),
    ])

    public let rules: [ShellRule]

    public func detect(from entries: [String]) -> ShellDetectionResult {
        for rule in rules {
            let hits = rule.requiredPatterns.filter { pattern in
                entries.contains { $0.localizedCaseInsensitiveContains(pattern) }
            }
            if hits.count == rule.requiredPatterns.count {
                return .init(vendor: rule.vendor, matchedFeatures: hits)
            }
        }
        return .init(vendor: "未识别到已知加固", matchedFeatures: [])
    }
}
```

- [ ] **Step 4: Add archive listing support**

```swift
import Foundation

public struct ArchiveReader {
    public init() {}

    public func listEntries(in apkURL: URL) throws -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-Z1", apkURL.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(decoding: data, as: UTF8.self)
            .split(separator: "\n")
            .map(String.init)
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `swift test --filter ShellDetectorTests`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add Sources/APKShellInspectorCore Tests/APKShellInspectorCoreTests
git commit -m "feat: add offline shell detection rules"
```

### Task 3: Implement Metadata Extraction and Analysis Orchestration

**Files:**
- Create: `Sources/APKShellInspectorCore/Models/APKMetadata.swift`
- Create: `Sources/APKShellInspectorCore/Models/APKAnalysisResult.swift`
- Create: `Sources/APKShellInspectorCore/Services/BinaryAndroidManifestParser.swift`
- Create: `Sources/APKShellInspectorCore/Services/CertificateExtractor.swift`
- Create: `Sources/APKShellInspectorCore/Services/APKAnalyzer.swift`
- Create: `Tests/APKShellInspectorCoreTests/ManifestParserTests.swift`
- Create: `Tests/APKShellInspectorCoreTests/APKAnalyzerTests.swift`

- [ ] **Step 1: Write the failing metadata tests**

```swift
import Foundation
import Testing
@testable import APKShellInspectorCore

@Test("returns unavailable values when manifest fields are missing")
func unavailableFallbacks() {
    let metadata = APKMetadata.empty(fileName: "demo.apk")

    #expect(metadata.packageName == "不可用")
    #expect(metadata.versionName == "不可用")
}
```

```swift
@Test("analyzer merges shell result with archive entries")
func analyzerMergesDetection() async throws {
    let analyzer = APKAnalyzer(
        archiveReader: StubArchiveReader(entries: ["lib/armeabi-v7a/libjiagu.so"]),
        manifestParser: StubManifestParser(),
        certificateExtractor: StubCertificateExtractor()
    )

    let result = try await analyzer.analyze(apkURL: URL(fileURLWithPath: "/tmp/demo.apk"))

    #expect(result.detection.vendor == "360加固")
    #expect(result.metadata.fileName == "demo.apk")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test --filter APKAnalyzerTests`
Expected: FAIL with missing `APKAnalyzer` and `APKMetadata`

- [ ] **Step 3: Implement metadata and analyzer glue**

```swift
public struct APKMetadata: Sendable {
    public let fileName: String
    public let packageName: String
    public let versionName: String
    public let versionCode: String
    public let minSDK: String
    public let targetSDK: String
    public let abiSummary: String
    public let certificateSummary: String

    public static func empty(fileName: String) -> APKMetadata {
        .init(
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
```

```swift
public struct APKAnalysisResult: Sendable {
    public let metadata: APKMetadata
    public let detection: ShellDetectionResult
    public let archiveEntries: [String]
    public let elapsedMilliseconds: Int
}
```

```swift
public actor APKAnalyzer {
    private let archiveReader: ArchiveReadering
    private let manifestParser: BinaryAndroidManifestParsing
    private let certificateExtractor: CertificateExtracting
    private let detector: ShellDetector

    public init(
        archiveReader: ArchiveReadering = ArchiveReader(),
        manifestParser: BinaryAndroidManifestParsing = BinaryAndroidManifestParser(),
        certificateExtractor: CertificateExtracting = CertificateExtractor(),
        detector: ShellDetector = .default
    ) {
        self.archiveReader = archiveReader
        self.manifestParser = manifestParser
        self.certificateExtractor = certificateExtractor
        self.detector = detector
    }
}
```

- [ ] **Step 4: Add a focused binary manifest parser test fixture**

```swift
@Test("parses package name and sdk values from a manifest fixture")
func parsesManifestFixture() throws {
    let data = try fixtureData(named: "manifest-minimal.bin")
    let parsed = try BinaryAndroidManifestParser().parse(data: data, fileName: "fixture.apk")

    #expect(parsed.packageName == "com.demo.shell")
    #expect(parsed.minSDK == "24")
    #expect(parsed.targetSDK == "34")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `swift test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add Sources/APKShellInspectorCore Tests/APKShellInspectorCoreTests
git commit -m "feat: analyze apk metadata and manifest"
```

### Task 4: Implement the SwiftUI Tool Window and App Bundle Packaging

**Files:**
- Create: `Sources/APKShellInspectorApp/ViewModels/AppViewModel.swift`
- Create: `Sources/APKShellInspectorApp/Views/ContentView.swift`
- Create: `Sources/APKShellInspectorApp/Views/DropZoneView.swift`
- Modify: `Sources/APKShellInspectorApp/APKShellInspectorApp.swift`
- Modify: `scripts/build-app.sh`
- Create: `Tests/APKShellInspectorCoreTests/AppViewModelTests.swift`

- [ ] **Step 1: Write the failing view-model test**

```swift
import Foundation
import Testing
@testable import APKShellInspectorApp

@Test("copy summary includes vendor and package")
func copySummaryIncludesCoreFields() async throws {
    let viewModel = AppViewModel(analyzer: .previewSucceeded)

    await viewModel.load(url: URL(fileURLWithPath: "/tmp/demo.apk"))

    #expect(viewModel.copySummary.contains("查壳结论"))
    #expect(viewModel.copySummary.contains("包名"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test --filter AppViewModelTests`
Expected: FAIL with missing `AppViewModel`

- [ ] **Step 3: Implement the classic Mac tool window**

```swift
struct ContentView: View {
    @StateObject private var viewModel = AppViewModel()

    var body: some View {
        VStack(spacing: 16) {
            HStack {
                TextField("选择 APK 文件", text: $viewModel.selectedPath)
                Button("选择文件") { viewModel.pickAPK() }
            }

            ResultPanelView(viewModel: viewModel)

            HStack {
                Text(viewModel.statusText)
                Spacer()
                Button("复制结果") { viewModel.copySummaryToPasteboard() }
                Button("退出") { NSApp.terminate(nil) }
            }
        }
        .padding(20)
        .frame(width: 760, height: 460)
    }
}
```

- [ ] **Step 4: Finish the build script with `Info.plist` and icon slot**

```bash
cat > "$APP_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>APKShellInspector</string>
  <key>CFBundleIdentifier</key><string>org.local.apkshellinspector</string>
  <key>CFBundleName</key><string>APKShellInspector</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>
PLIST
```

- [ ] **Step 5: Run verification commands**

Run: `swift test`
Expected: PASS

Run: `scripts/build-app.sh`
Expected: creates `dist/APKShellInspector.app`

- [ ] **Step 6: Commit**

```bash
git add Sources/APKShellInspectorApp scripts Tests/APKShellInspectorCoreTests
git commit -m "feat: add mac app shell inspector ui"
```
