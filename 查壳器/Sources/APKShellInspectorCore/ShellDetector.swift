import Foundation

public struct ShellIndicator: Sendable {
    public let label: String
    public let patterns: [String]
    public let weight: Int

    public init(label: String, patterns: [String], weight: Int) {
        self.label = label
        self.patterns = patterns
        self.weight = weight
    }
}

public struct ShellFamily: Sendable {
    public let vendor: String
    public let indicators: [ShellIndicator]
    public let threshold: Int
    public let priority: Int

    public init(vendor: String, indicators: [ShellIndicator], threshold: Int, priority: Int = 0) {
        self.vendor = vendor
        self.indicators = indicators
        self.threshold = threshold
        self.priority = priority
    }
}

public struct SuspicionIndicator: Sendable {
    public let label: String
    public let patterns: [String]
    public let weight: Int

    public init(label: String, patterns: [String], weight: Int) {
        self.label = label
        self.patterns = patterns
        self.weight = weight
    }
}

public struct ShellDetector: Sendable {
    public static let `default` = ShellDetector(
        families: [
            .init(
                vendor: "梆梆加固",
                indicators: [
                    .init(label: "assets/bangcle", patterns: ["assets/bangcle"], weight: 4),
                    .init(label: "libsecexe.so", patterns: ["libsecexe.so"], weight: 4),
                    .init(label: "libbangcle_risk.so", patterns: ["libbangcle_risk.so"], weight: 3),
                    .init(label: "riskstub", patterns: ["riskstub.dex"], weight: 2),
                    .init(label: "libriskstub.so", patterns: ["libriskstub.so"], weight: 1),
                ],
                threshold: 3,
                priority: 100
            ),
            .init(
                vendor: "娜迦加固",
                indicators: [
                    .init(label: "enc.mf", patterns: ["enc.mf"], weight: 2),
                    .init(label: "libnmg.so", patterns: ["libnmg.so"], weight: 2),
                    .init(label: "libsqlite_encrypt.so", patterns: ["libsqlite_encrypt.so"], weight: 2),
                    .init(label: "assets/meta-data/manifest.mf", patterns: ["assets/meta-data/manifest.mf"], weight: 1),
                    .init(label: "assets/meta-data/rsa.sig", patterns: ["assets/meta-data/rsa.sig"], weight: 1),
                    .init(label: "libjade2", patterns: ["libjade2_"], weight: 1),
                    .init(label: "libvdog", patterns: ["libvdog.so", "libvdog"], weight: 1),
                ],
                threshold: 3,
                priority: 94
            ),
            .init(
                vendor: "360加固",
                indicators: [
                    .init(label: "libjiagu.so", patterns: ["libjiagu.so"], weight: 3),
                ],
                threshold: 3,
                priority: 90
            ),
            .init(
                vendor: "爱加密",
                indicators: [
                    .init(label: "ijiami", patterns: ["ijiami"], weight: 2),
                    .init(label: "libexecmain.so", patterns: ["libexecmain.so"], weight: 2),
                ],
                threshold: 2,
                priority: 80
            ),
            .init(
                vendor: "腾讯御安全",
                indicators: [
                    .init(label: "libtosprotection", patterns: ["libtosprotection"], weight: 3),
                ],
                threshold: 3,
                priority: 70
            ),
            .init(
                vendor: "阿里聚安全",
                indicators: [
                    .init(label: "libmobisec", patterns: ["libmobisec"], weight: 2),
                    .init(label: "sgmain", patterns: ["sgmain"], weight: 1),
                ],
                threshold: 2,
                priority: 60
            ),
            .init(
                vendor: "网易易盾",
                indicators: [
                    .init(label: "libnesec", patterns: ["libnesec"], weight: 2),
                    .init(label: "assets/nesec", patterns: ["assets/nesec"], weight: 1),
                ],
                threshold: 2,
                priority: 50
            ),
        ],
        suspiciousIndicators: [
            .init(label: "libDexHelper", patterns: ["libdexhelper.so", "libdexhelper-x86.so"], weight: 2),
            .init(label: "libzeus_direct_dex.so", patterns: ["libzeus_direct_dex.so"], weight: 2),
            .init(label: "libJMEncryptBox.so", patterns: ["libjmencryptbox.so"], weight: 1),
            .init(label: "libEncryptorP.so", patterns: ["libencryptorp.so"], weight: 1),
            .init(label: "libsecApi.so", patterns: ["libsecapi.so"], weight: 1),
            .init(label: "assets/meta-data/manifest.mf", patterns: ["assets/meta-data/manifest.mf"], weight: 1),
            .init(label: "assets/meta-data/rsa.sig", patterns: ["assets/meta-data/rsa.sig"], weight: 1),
            .init(label: "assets/meta-data/rsa.pub", patterns: ["assets/meta-data/rsa.pub"], weight: 1),
            .init(label: "libjade2", patterns: ["libjade2_"], weight: 1),
            .init(label: "libvdog", patterns: ["libvdog.so", "libvdog"], weight: 1),
            .init(label: "libnmg.so", patterns: ["libnmg.so"], weight: 1),
            .init(label: "libsqlite_encrypt.so", patterns: ["libsqlite_encrypt.so"], weight: 1),
        ],
        genericSuspicionThreshold: 3,
        familyLeaningThreshold: 2
    )

    public let families: [ShellFamily]
    public let suspiciousIndicators: [SuspicionIndicator]
    public let genericSuspicionThreshold: Int
    public let familyLeaningThreshold: Int

    public init(
        families: [ShellFamily],
        suspiciousIndicators: [SuspicionIndicator],
        genericSuspicionThreshold: Int,
        familyLeaningThreshold: Int
    ) {
        self.families = families
        self.suspiciousIndicators = suspiciousIndicators
        self.genericSuspicionThreshold = genericSuspicionThreshold
        self.familyLeaningThreshold = familyLeaningThreshold
    }

    public func detect(from entries: [String]) -> ShellDetectionResult {
        let normalizedEntries = entries.map { $0.lowercased() }
        let familyCandidates = families.compactMap { evaluateFamily($0, entries: normalizedEntries) }
        let rankedFamilies = familyCandidates.sorted(by: Candidate.sort)

        if let winner = rankedFamilies.first, winner.score >= winner.family.threshold {
            let confidence = winner.score >= (winner.family.threshold + 2) || winner.indicators.count >= 3 ? "高" : "中"
            return ShellDetectionResult(
                vendor: winner.family.vendor,
                matchedFeatures: winner.indicators.map(\.label),
                confidence: confidence,
                verdict: winner.family.vendor,
                rationale: "命中高置信家族特征，可直接判定为 \(winner.family.vendor)。",
                disposition: .detectedKnown
            )
        }

        let suspicion = evaluateSuspicion(entries: normalizedEntries)

        if let leaning = leaningFamily(from: rankedFamilies), leaning.score >= familyLeaningThreshold {
            return ShellDetectionResult(
                vendor: leaning.family.vendor,
                matchedFeatures: unique(leaning.indicators.map(\.label) + suspicion.indicators.map(\.label)),
                confidence: "中",
                verdict: "疑似加固（偏向\(leaning.family.vendor)）",
                rationale: "命中部分家族特征，但分数不足以直接确认厂商；当前更偏向 \(leaning.family.vendor) 家族特征。",
                disposition: .suspectedFamily
            )
        }

        if suspicion.score >= genericSuspicionThreshold {
            return ShellDetectionResult(
                vendor: "疑似存在加固",
                matchedFeatures: suspicion.indicators.map(\.label),
                confidence: "中",
                verdict: "疑似存在加固",
                rationale: "命中通用可疑特征簇，存在 loader/保护器残留，但暂无法确认具体厂商。",
                disposition: .suspectedUnknown
            )
        }

        return ShellDetectionResult(
            vendor: "未识别到已知加固",
            matchedFeatures: [],
            confidence: "未命中内置规则",
            verdict: "未识别到已知加固",
            rationale: "未命中已知家族特征或通用可疑壳簇。",
            disposition: .unknown
        )
    }

    private func evaluateFamily(_ family: ShellFamily, entries: [String]) -> Candidate? {
        let matched = family.indicators.compactMap { indicator -> ShellIndicator? in
            let hits = indicator.patterns.contains { pattern in
                entries.contains { entry in
                    matches(entry: entry, pattern: pattern)
                }
            }
            return hits ? indicator : nil
        }

        guard !matched.isEmpty else {
            return nil
        }

        let score = matched.reduce(into: 0) { $0 += $1.weight }
        return Candidate(family: family, indicators: matched, score: score)
    }

    private func evaluateSuspicion(entries: [String]) -> SuspicionCandidate {
        let matched = suspiciousIndicators.compactMap { indicator -> SuspicionIndicator? in
            let hits = indicator.patterns.contains { pattern in
                entries.contains { entry in
                    matches(entry: entry, pattern: pattern)
                }
            }
            return hits ? indicator : nil
        }

        let score = matched.reduce(into: 0) { $0 += $1.weight }
        return SuspicionCandidate(indicators: matched, score: score)
    }

    private func leaningFamily(from rankedFamilies: [Candidate]) -> Candidate? {
        guard let first = rankedFamilies.first else {
            return nil
        }

        if rankedFamilies.count == 1 {
            return first
        }

        let second = rankedFamilies[1]
        return first.score > second.score ? first : nil
    }

    private func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }

    private func matches(entry: String, pattern: String) -> Bool {
        let normalizedPattern = pattern.lowercased()
        let basename = entry.split(separator: "/").last.map(String.init) ?? entry

        if normalizedPattern.hasSuffix("_") {
            return basename.hasPrefix(normalizedPattern)
        }

        if normalizedPattern.contains("/") {
            return entry.contains(normalizedPattern)
        }

        if isArtifactPattern(normalizedPattern) {
            return matchesArtifactBasename(pattern: normalizedPattern, basename: basename)
        }

        let components = entry.split(separator: "/").map(String.init)
        return components.contains { component in
            containsDelimitedToken(component, token: normalizedPattern)
        }
    }

    private func isArtifactPattern(_ pattern: String) -> Bool {
        [".so", ".dex", ".mf", ".sig", ".pub"].contains { pattern.hasSuffix($0) }
    }

    private func matchesArtifactBasename(pattern: String, basename: String) -> Bool {
        guard let extensionStart = pattern.lastIndex(of: ".") else {
            return basename == pattern
        }

        let stem = String(pattern[..<extensionStart])
        let suffix = String(pattern[extensionStart...])

        guard basename.hasSuffix(suffix) else {
            return false
        }

        let basenameStem = String(basename.dropLast(suffix.count))
        return basenameStem == stem
            || basenameStem.hasPrefix("\(stem)_")
            || basenameStem.hasPrefix("\(stem)-")
    }

    private func containsDelimitedToken(_ value: String, token: String) -> Bool {
        guard let range = value.range(of: token) else {
            return false
        }

        let before = range.lowerBound > value.startIndex ? value[value.index(before: range.lowerBound)] : nil
        let after = range.upperBound < value.endIndex ? value[range.upperBound] : nil

        return isTokenBoundary(before) && isTokenBoundary(after)
    }

    private func isTokenBoundary(_ character: Character?) -> Bool {
        guard let character else {
            return true
        }

        return !character.isLetter && !character.isNumber
    }
}

private struct Candidate {
    let family: ShellFamily
    let indicators: [ShellIndicator]
    let score: Int

    static func sort(lhs: Candidate, rhs: Candidate) -> Bool {
        if lhs.score != rhs.score {
            return lhs.score > rhs.score
        }
        if lhs.indicators.count != rhs.indicators.count {
            return lhs.indicators.count > rhs.indicators.count
        }
        return lhs.family.priority > rhs.family.priority
    }
}

private struct SuspicionCandidate {
    let indicators: [SuspicionIndicator]
    let score: Int
}
