# Shell Detection Generalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade shell detection from vendor-only exact matches to layered detection that can emit known vendor detections, family-leaning suspicions, and generic shell suspicions without flooding false positives.

**Architecture:** Extend the shell detection result model with verdict/rationale/disposition, keep weighted vendor families, and add a second suspicious-indicator pass for generic loader/protector clusters. Let the app UI render the richer verdict and rationale instead of treating everything as binary known/unknown.

**Tech Stack:** Swift 6, Foundation, SwiftUI, Swift Testing

---

### Task 1: Extend detection result semantics

**Files:**
- Modify: `Sources/APKShellInspectorCore/Models.swift`
- Modify: `Sources/APKShellInspectorApp/AppViewModel.swift`
- Test: `Tests/APKShellInspectorAppTests/AppViewModelTests.swift`

- [ ] Write failing tests for suspected verdict rendering.
- [ ] Run `swift test --filter AppViewModelTests` and verify failure.
- [ ] Add `ShellDetectionDisposition`, `verdict`, and `rationale`.
- [ ] Update view-model shell/status text generation to use the richer result.
- [ ] Re-run `swift test --filter AppViewModelTests` and verify pass.

### Task 2: Add family-leaning and generic suspicion tests

**Files:**
- Modify: `Tests/APKShellInspectorCoreTests/ShellDetectorTests.swift`
- Modify: `Sources/APKShellInspectorCore/ShellDetector.swift`

- [ ] Write failing tests for:
  - family leaning (`疑似加固（偏向娜迦加固）`)
  - generic suspicious cluster (`疑似存在加固`)
  - non-suspicious business assets remaining unknown
- [ ] Run `swift test --filter ShellDetectorTests` and verify failure.
- [ ] Implement layered detection with vendor families plus generic suspicious indicators.
- [ ] Re-run `swift test --filter ShellDetectorTests` and verify pass.

### Task 3: Verify end-to-end behavior

**Files:**
- Modify: `Sources/APKShellInspectorApp/ContentView.swift`
- Modify: `Sources/APKShellInspectorCore/APKAnalyzer.swift` (if copy summary needs verdict text)

- [ ] Update result panel to show verdict and rationale.
- [ ] Run `swift test` and verify all tests pass.
- [ ] Run `./scripts/build-app.sh` and verify the distributable app is rebuilt.
