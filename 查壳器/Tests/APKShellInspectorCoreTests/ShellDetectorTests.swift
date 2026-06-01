import Testing
@testable import APKShellInspectorCore

@Test("detects Bangcle from well-known entry names")
func detectsBangcle() {
    let result = ShellDetector.default.detect(from: [
        "assets/bangcleplugin/container.dex",
        "lib/armeabi-v7a/libsecexe.so",
    ])

    #expect(result.vendor == "梆梆加固")
    #expect(result.matchedFeatures.count == 2)
}

@Test("returns unknown when no shell signature matches")
func detectsUnknown() {
    let result = ShellDetector.default.detect(from: [
        "classes.dex",
        "AndroidManifest.xml",
    ])

    #expect(result.vendor == "未识别到已知加固")
    #expect(result.matchedFeatures.isEmpty)
}

@Test("detects Bangcle from RiskStub and bangcle risk libraries")
func detectsBangcleFromRiskStub() {
    let result = ShellDetector.default.detect(from: [
        "assets/RiskStub.dex",
        "assets/arm64-v8a/libRiskStub.so",
        "lib/armeabi-v7a/libbangcle_risk.so",
    ])

    #expect(result.vendor == "梆梆加固")
    #expect(result.matchedFeatures.contains("libbangcle_risk.so"))
}

@Test("detects Naga from VDog-style enc manifest and native libraries")
func detectsNagaFromVdogStyleAssets() {
    let result = ShellDetector.default.detect(from: [
        "assets/meta-inf/enc.mf",
        "lib/armeabi/libsqlite_encrypt.so",
        "lib/armeabi/libnMg.so",
        "lib/armeabi/libjade2_LF8bOvWP4.so",
    ])

    #expect(result.vendor == "娜迦加固")
    #expect(result.matchedFeatures.contains("enc.mf"))
}

@Test("detects Bangcle from broader risk loader family signals")
func detectsBangcleFromFamilySignals() {
    let result = ShellDetector.default.detect(from: [
        "assets/runtime/RiskStub.dex",
        "lib/arm64-v8a/libRiskStub.so",
    ])

    #expect(result.vendor == "梆梆加固")
    #expect(result.confidence == "中")
    #expect(result.matchedFeatures.contains("riskstub"))
}

@Test("detects Naga from family indicators without exact legacy tuple")
func detectsNagaFromFamilySignals() {
    let result = ShellDetector.default.detect(from: [
        "assets/meta-inf/enc.mf",
        "lib/arm64-v8a/libvdog.so",
    ])

    #expect(result.vendor == "娜迦加固")
    #expect(result.confidence == "中")
    #expect(result.matchedFeatures.contains("libvdog"))
}

@Test("detects Naga from jade assets signature cluster")
func detectsNagaFromJadeAssetCluster() {
    let result = ShellDetector.default.detect(from: [
        "assets/meta-data/manifest.mf",
        "assets/meta-data/rsa.sig",
        "lib/armeabi-v7a/libjade2_LF8bOvWP4.so",
    ])

    #expect(result.vendor == "娜迦加固")
    #expect(result.matchedFeatures.contains("assets/meta-data/manifest.mf"))
    #expect(result.matchedFeatures.contains("libjade2"))
}

@Test("returns family-leaning suspicion when only partial Naga features match")
func detectsFamilyLeaningSuspicion() {
    let result = ShellDetector.default.detect(from: [
        "assets/meta-data/manifest.mf",
        "lib/armeabi-v7a/libjade2_LF8bOvWP4.so",
    ])

    #expect(result.disposition == .suspectedFamily)
    #expect(result.vendor == "娜迦加固")
    #expect(result.verdict == "疑似加固（偏向娜迦加固）")
    #expect(result.rationale.contains("家族特征"))
}

@Test("returns generic suspicion for suspicious loader cluster without vendor certainty")
func detectsGenericSuspicion() {
    let result = ShellDetector.default.detect(from: [
        "lib/armeabi-v7a/libDexHelper.so",
        "lib/armeabi-v7a/libzeus_direct_dex.so",
    ])

    #expect(result.disposition == .suspectedUnknown)
    #expect(result.verdict == "疑似存在加固")
    #expect(result.rationale.contains("通用可疑特征"))
}

@Test("does not raise suspicion for ordinary business assets")
func avoidsFalsePositiveForBusinessAssets() {
    let result = ShellDetector.default.detect(from: [
        "assets/liveness_20190614_encrypt.bin",
        "res/xml/network_security_config.xml",
        "lib/armeabi-v7a/libRSSupport.so",
    ])

    #expect(result.disposition == .unknown)
    #expect(result.verdict == "未识别到已知加固")
}
