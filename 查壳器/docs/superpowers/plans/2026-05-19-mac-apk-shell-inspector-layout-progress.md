# Mac APK Shell Inspector Layout & Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework the Mac APK shell inspector window to match the classic tool-style layout from the reference image, and add a bottom progress bar with explicit Chinese step labels showing exactly which parsing stage is running.

**Architecture:** Keep the existing Swift Package structure. Add a reusable progress-stage model in the core analyzer, emit stage callbacks from `APKAnalyzer`, and let `AppViewModel` translate those callbacks into UI state. Rebuild `ContentView` into a three-zone classic tool window: top file row, middle description/results panel, and bottom progress + shell result row.

**Tech Stack:** Swift 6, SwiftUI, Foundation, Swift Testing, existing `APKShellInspectorCore` + `APKShellInspectorApp`

---

### Task 1: Add Progress Stage Modeling and Tests

**Files:**
- Modify: `Package.swift`
- Modify: `Sources/APKShellInspectorCore/Models.swift`
- Modify: `Sources/APKShellInspectorCore/APKAnalyzer.swift`
- Create: `Tests/APKShellInspectorCoreTests/AppViewModelTests.swift`

- [ ] **Step 1: Write the failing progress tests**

```swift
import Foundation
import Testing
@testable import APKShellInspectorApp
@testable import APKShellInspectorCore

@MainActor
@Test("view model exposes Chinese progress labels in analyzer order")
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
@Test("view model keeps the failed stage label when analysis throws")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test --filter AppViewModelTests`
Expected: FAIL with missing `progressLabel`, `progressValue`, or analyzer stub helpers

- [ ] **Step 3: Implement minimal progress-stage support**

```swift
public enum AnalysisStage: Int, CaseIterable, Sendable {
    case validating = 1
    case readingManifest
    case extractingMetadata
    case matchingShell
    case finalizing
}

public struct AnalysisProgress: Sendable, Equatable {
    public let stage: AnalysisStage
    public let label: String
    public let fractionCompleted: Double
}
```

```swift
public func analyze(
    apkURL: URL,
    progress: (@Sendable (AnalysisProgress) async -> Void)? = nil
) async throws -> APKAnalysisResult
```

- [ ] **Step 4: Update `AppViewModel` state**

```swift
@Published var progressLabel = ""
@Published var progressValue = 0.0
@Published var shellSummary = "此 APK 未采用加固或尚未开始解析。"
```

- [ ] **Step 5: Run test to verify it passes**

Run: `swift test --filter AppViewModelTests`
Expected: PASS

### Task 2: Rebuild the Window into the Reference-Style Layout

**Files:**
- Modify: `Sources/APKShellInspectorApp/ContentView.swift`
- Modify: `Sources/APKShellInspectorApp/AppViewModel.swift`

- [ ] **Step 1: Write the failing shell summary test**

```swift
@MainActor
@Test("shell summary falls back to analyzing text while work is running")
func shellSummaryShowsAnalyzingState() {
    let viewModel = AppViewModel(analyzer: .previewSucceeded)

    viewModel.beginProgressPreview()

    #expect(viewModel.shellSummary == "正在分析...")
    #expect(viewModel.progressLabel.contains("第 1/5 步"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test --filter AppViewModelTests`
Expected: FAIL with missing preview helper or shell summary state

- [ ] **Step 3: Implement the classic B-layout**

```swift
VStack(spacing: 10) {
    fileRow
    resultPanel
    VStack(spacing: 6) {
        Text(viewModel.progressLabel)
        ProgressView(value: viewModel.progressValue)
        shellRow
    }
}
```

- [ ] **Step 4: Preserve core behaviors**

```swift
// Keep:
// - drag and drop
// - file picker
// - copy result action
// - exit action
```

- [ ] **Step 5: Run the full verification**

Run: `swift test`
Expected: PASS

Run: `./scripts/build-app.sh`
Expected: PASS and rebuild `dist/APKShellInspector.app`
