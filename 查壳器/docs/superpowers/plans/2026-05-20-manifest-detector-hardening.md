# Manifest Parser & Shell Detector Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix real-world APK metadata extraction failures and upgrade shell detection so the app can infer shell families from broader signature clusters instead of relying on one-off exact matches.

**Architecture:** Keep the analyzer pipeline intact, but replace the fragile manifest parser assumptions with a chunk-aware binary AXML walker that respects top-level header size, optional resource-map/namespace chunks, and start-element attribute offsets. Upgrade shell detection from flat exact-match rules to vendor family heuristics with weighted indicators, minimum-score thresholds, and matched-evidence reporting.

**Tech Stack:** Swift 6, Foundation, Swift Testing, existing `APKShellInspectorCore` + `APKShellInspectorApp`

---

### Task 1: Harden Binary AndroidManifest Parsing

**Files:**
- Modify: `Sources/APKShellInspectorCore/BinaryAndroidManifestParser.swift`
- Modify: `Tests/APKShellInspectorCoreTests/ManifestParserTests.swift`

- [ ] **Step 1: Write the failing parser regression test**

```swift
@Test("parses package and sdk values from a manifest with 12-byte xml header and extra chunks")
func parsesManifestWithRealWorldChunkLayout() throws {
    let data = ManifestFixtureBuilder.makeRealWorldLikeManifest()

    let parsed = try BinaryAndroidManifestParser().parse(data: data, fileName: "real.apk")

    #expect(parsed.packageName == "com.demo.real")
    #expect(parsed.versionName == "5.2.1-rc19")
    #expect(parsed.versionCode == "50201")
    #expect(parsed.minSDK == "21")
    #expect(parsed.targetSDK == "30")
}
```

- [ ] **Step 2: Run the parser test to verify it fails**

Run: `swift test --filter ManifestParserTests`
Expected: FAIL because the parser starts scanning at byte `8`, misses the string pool, and leaves metadata as `不可用`

- [ ] **Step 3: Implement a chunk-aware parser**

```swift
let xmlHeaderSize = Int(data.readUInt16(at: 2))
var offset = xmlHeaderSize

while offset + 8 <= data.count {
    let chunkType = data.readUInt16(at: offset)
    let headerSize = Int(data.readUInt16(at: offset + 2))
    let chunkSize = Int(data.readUInt32(at: offset + 4))
    ...
}
```

```swift
switch chunkType {
case stringPoolChunkType:
    stringPool = try parseStringPool(in: data, offset: offset)
case startElementChunkType:
    parseStartElement(in: data, offset: offset, strings: stringPool, metadata: &metadata)
case resourceMapChunkType, startNamespaceChunkType, endNamespaceChunkType:
    break
default:
    break
}
```

- [ ] **Step 4: Re-run the parser test to verify it passes**

Run: `swift test --filter ManifestParserTests`
Expected: PASS

### Task 2: Upgrade Shell Detection to Family Heuristics

**Files:**
- Modify: `Sources/APKShellInspectorCore/ShellDetector.swift`
- Modify: `Tests/APKShellInspectorCoreTests/ShellDetectorTests.swift`

- [ ] **Step 1: Write the failing heuristic tests**

```swift
@Test("detects Bangcle from broader risk loader family signals")
func detectsBangcleFromFamilySignals() {
    let result = ShellDetector.default.detect(from: [
        "assets/runtime/RiskStub.dex",
        "lib/arm64-v8a/libRiskStub.so"
    ])

    #expect(result.vendor == "梆梆加固")
    #expect(result.confidence == "中")
}

@Test("detects Naga from family indicators without requiring one exact rule tuple")
func detectsNagaFromFamilySignals() {
    let result = ShellDetector.default.detect(from: [
        "assets/meta-inf/enc.mf",
        "lib/arm64-v8a/libvdog.so"
    ])

    #expect(result.vendor == "娜迦加固")
    #expect(result.matchedFeatures.contains("libvdog"))
}
```

- [ ] **Step 2: Run the shell detector tests to verify they fail**

Run: `swift test --filter ShellDetectorTests`
Expected: FAIL because `ShellDetector` only supports flat pattern tuples and cannot score family indicators

- [ ] **Step 3: Implement weighted family detection**

```swift
public struct ShellFamily {
    let vendor: String
    let indicators: [ShellIndicator]
    let threshold: Int
    let priority: Int
}

public struct ShellIndicator {
    let pattern: String
    let weight: Int
}
```

```swift
let score = matchedIndicators.reduce(into: 0) { $0 += $1.weight }
guard score >= family.threshold else { return nil }
```

- [ ] **Step 4: Re-run the shell detector tests to verify they pass**

Run: `swift test --filter ShellDetectorTests`
Expected: PASS

### Task 3: Verify Analyzer Integration End-to-End

**Files:**
- Modify: `Sources/APKShellInspectorCore/APKAnalyzer.swift` (only if needed for integration cleanup)
- Modify: `Tests/APKShellInspectorCoreTests/ManifestParserTests.swift`
- Modify: `Tests/APKShellInspectorCoreTests/ShellDetectorTests.swift`

- [ ] **Step 1: Run the full core test suite**

Run: `swift test`
Expected: PASS with all parser and detector regressions green

- [ ] **Step 2: Rebuild the distributable app**

Run: `./scripts/build-app.sh`
Expected: PASS and rebuild `dist/APKShellInspector.app`

- [ ] **Step 3: Commit the hardening work**

```bash
git add docs/superpowers/plans/2026-05-20-manifest-detector-hardening.md Sources/APKShellInspectorCore/BinaryAndroidManifestParser.swift Sources/APKShellInspectorCore/ShellDetector.swift Tests/APKShellInspectorCoreTests/ManifestParserTests.swift Tests/APKShellInspectorCoreTests/ShellDetectorTests.swift
git commit -m "feat: harden manifest parsing and shell detection"
```
