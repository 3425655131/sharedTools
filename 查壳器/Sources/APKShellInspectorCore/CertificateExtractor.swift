import Foundation

public protocol CertificateExtracting: Sendable {
    func extractSummary(from apkURL: URL, entries: [String], archiveReader: ArchiveReading) throws -> String
}

public struct CertificateExtractor: CertificateExtracting {
    public init() {}

    public func extractSummary(from apkURL: URL, entries: [String], archiveReader: ArchiveReading) throws -> String {
        guard let signatureEntry = entries.first(where: {
            let upper = $0.uppercased()
            return upper.hasPrefix("META-INF/") && (upper.hasSuffix(".RSA") || upper.hasSuffix(".DSA") || upper.hasSuffix(".EC"))
        }) else {
            return "不可用"
        }

        let signatureData = try archiveReader.readEntry(named: signatureEntry, from: apkURL)
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let derURL = tempDirectory.appendingPathComponent("signature.der")
        try signatureData.write(to: derURL)

        let pem = try runCommand(
            executable: "/usr/bin/openssl",
            arguments: ["pkcs7", "-inform", "DER", "-in", derURL.path, "-print_certs"]
        )

        guard !pem.isEmpty else {
            return "不可用"
        }

        let x509 = try runCommand(
            executable: "/usr/bin/openssl",
            arguments: ["x509", "-noout", "-fingerprint", "-sha256", "-subject"],
            input: Data(pem.utf8)
        )

        let lines = x509
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }

        let fingerprint = lines.first(where: { $0.contains("SHA256 Fingerprint=") })?
            .replacingOccurrences(of: "SHA256 Fingerprint=", with: "")
        let subject = lines.first(where: { $0.hasPrefix("subject=") })?
            .replacingOccurrences(of: "subject=", with: "")

        let parts = [subject, fingerprint].compactMap { $0 }.filter { !$0.isEmpty }
        return parts.isEmpty ? "不可用" : parts.joined(separator: " | ")
    }
}
