import Foundation

public protocol BinaryAndroidManifestParsing: Sendable {
    func parse(data: Data, fileName: String) throws -> APKMetadata
}

public struct BinaryAndroidManifestParser: BinaryAndroidManifestParsing {
    private let stringPoolChunkType: UInt16 = 0x0001
    private let xmlChunkType: UInt16 = 0x0003
    private let startElementChunkType: UInt16 = 0x0102
    private let startNamespaceChunkType: UInt16 = 0x0100
    private let endNamespaceChunkType: UInt16 = 0x0101
    private let resourceMapChunkType: UInt16 = 0x0180
    private let utf8Flag: UInt32 = 0x00000100
    private let stringValueType: UInt8 = 0x03
    private let intValueType: UInt8 = 0x10
    private let xmlMinimumHeaderSize = 8
    private let xmlNodeHeaderSize = 16

    public init() {}

    public func parse(data: Data, fileName: String) throws -> APKMetadata {
        guard data.count >= xmlMinimumHeaderSize, data.readUInt16(at: 0) == xmlChunkType else {
            throw APKAnalysisError.unreadableArchive
        }

        let xmlHeaderSize = Int(data.readUInt16(at: 2))
        guard xmlHeaderSize >= xmlMinimumHeaderSize, xmlHeaderSize <= data.count else {
            throw APKAnalysisError.unreadableArchive
        }

        var stringPool: [String] = []
        var metadata = APKMetadata.empty(fileName: fileName)
        var offset = xmlHeaderSize

        while offset + 8 <= data.count {
            let chunkType = data.readUInt16(at: offset)
            let headerSize = Int(data.readUInt16(at: offset + 2))
            let chunkSize = Int(data.readUInt32(at: offset + 4))
            guard headerSize >= 8, chunkSize >= headerSize, offset + chunkSize <= data.count else {
                break
            }

            switch chunkType {
            case stringPoolChunkType:
                stringPool = try parseStringPool(in: data, offset: offset)
            case startElementChunkType:
                parseStartElement(
                    in: data,
                    offset: offset,
                    strings: stringPool,
                    metadata: &metadata
                )
            case startNamespaceChunkType, endNamespaceChunkType, resourceMapChunkType:
                break
            default:
                break
            }

            offset += chunkSize
        }

        return metadata
    }

    private func parseStringPool(in data: Data, offset: Int) throws -> [String] {
        let headerSize = Int(data.readUInt16(at: offset + 2))
        let stringCount = Int(data.readUInt32(at: offset + 8))
        let flags = data.readUInt32(at: offset + 16)
        let stringsStart = Int(data.readUInt32(at: offset + 20))
        let isUTF8 = (flags & utf8Flag) != 0
        let stringOffsetsStart = offset + headerSize

        var strings: [String] = []
        strings.reserveCapacity(stringCount)

        for index in 0..<stringCount {
            let stringOffset = Int(data.readUInt32(at: stringOffsetsStart + (index * 4)))
            let absoluteOffset = offset + stringsStart + stringOffset
            strings.append(try decodeString(in: data, offset: absoluteOffset, utf8: isUTF8))
        }

        return strings
    }

    private func decodeString(in data: Data, offset: Int, utf8: Bool) throws -> String {
        guard offset < data.count else {
            throw APKAnalysisError.unreadableArchive
        }

        if utf8 {
            let (_, utf16LengthBytes) = readLength8(in: data, offset: offset)
            let byteLengthStart = offset + utf16LengthBytes
            let (byteLength, byteLengthBytes) = readLength8(in: data, offset: byteLengthStart)
            let bytesStart = byteLengthStart + byteLengthBytes
            guard bytesStart + byteLength <= data.count else {
                throw APKAnalysisError.unreadableArchive
            }
            let bytes = data.subdata(in: bytesStart..<(bytesStart + byteLength))
            guard let decoded = String(data: bytes, encoding: .utf8) else {
                throw APKAnalysisError.unreadableArchive
            }
            return decoded
        }

        let (characterLength, lengthBytes) = readLength16(in: data, offset: offset)
        let bytesStart = offset + lengthBytes
        let byteLength = characterLength * 2
        guard bytesStart + byteLength <= data.count else {
            throw APKAnalysisError.unreadableArchive
        }
        let bytes = data.subdata(in: bytesStart..<(bytesStart + byteLength))
        guard let decoded = String(data: bytes, encoding: .utf16LittleEndian) else {
            throw APKAnalysisError.unreadableArchive
        }
        return decoded
    }

    private func parseStartElement(
        in data: Data,
        offset: Int,
        strings: [String],
        metadata: inout APKMetadata
    ) {
        let nameIndex = Int(data.readUInt32(at: offset + 20))
        guard let elementName = strings[safe: nameIndex] else {
            return
        }

        let attributeStart = Int(data.readUInt16(at: offset + 24))
        let attributeSize = Int(data.readUInt16(at: offset + 26))
        let attributeCount = Int(data.readUInt16(at: offset + 28))
        guard attributeSize >= 20 else {
            return
        }

        let attributesOffset = offset + xmlNodeHeaderSize + attributeStart

        for attributeIndex in 0..<attributeCount {
            let attributeOffset = attributesOffset + (attributeIndex * attributeSize)
            guard attributeOffset + 20 <= data.count else {
                return
            }
            let attributeNameIndex = Int(data.readUInt32(at: attributeOffset + 4))
            let rawValueIndex = Int(data.readUInt32(at: attributeOffset + 8))
            let valueType = data.readUInt8(at: attributeOffset + 15)
            let valueData = data.readUInt32(at: attributeOffset + 16)

            guard let attributeName = strings[safe: attributeNameIndex] else {
                continue
            }

            let value = resolveAttributeValue(
                rawValueIndex: rawValueIndex,
                valueType: valueType,
                valueData: valueData,
                strings: strings
            )

            switch (elementName, attributeName) {
            case ("manifest", "package"):
                metadata = updated(metadata, packageName: value)
            case ("manifest", "versionName"):
                metadata = updated(metadata, versionName: value)
            case ("manifest", "versionCode"):
                metadata = updated(metadata, versionCode: value)
            case ("uses-sdk", "minSdkVersion"):
                metadata = updated(metadata, minSDK: value)
            case ("uses-sdk", "targetSdkVersion"):
                metadata = updated(metadata, targetSDK: value)
            default:
                continue
            }
        }
    }

    private func updated(
        _ metadata: APKMetadata,
        packageName: String? = nil,
        versionName: String? = nil,
        versionCode: String? = nil,
        minSDK: String? = nil,
        targetSDK: String? = nil
    ) -> APKMetadata {
        APKMetadata(
            fileName: metadata.fileName,
            packageName: packageName ?? metadata.packageName,
            versionName: versionName ?? metadata.versionName,
            versionCode: versionCode ?? metadata.versionCode,
            minSDK: minSDK ?? metadata.minSDK,
            targetSDK: targetSDK ?? metadata.targetSDK,
            abiSummary: metadata.abiSummary,
            certificateSummary: metadata.certificateSummary
        )
    }

    private func resolveAttributeValue(
        rawValueIndex: Int,
        valueType: UInt8,
        valueData: UInt32,
        strings: [String]
    ) -> String? {
        if rawValueIndex != Int(UInt32.max), let rawValue = strings[safe: rawValueIndex] {
            return rawValue
        }

        if valueType == stringValueType, let stringValue = strings[safe: Int(valueData)] {
            return stringValue
        }

        if valueType == intValueType {
            return String(valueData)
        }

        return nil
    }

    private func readLength8(in data: Data, offset: Int) -> (Int, Int) {
        let first = Int(data.readUInt8(at: offset))
        if (first & 0x80) == 0 {
            return (first, 1)
        }
        let second = Int(data.readUInt8(at: offset + 1))
        return (((first & 0x7F) << 8) | second, 2)
    }

    private func readLength16(in data: Data, offset: Int) -> (Int, Int) {
        let first = Int(data.readUInt16(at: offset))
        if (first & 0x8000) == 0 {
            return (first, 2)
        }
        let second = Int(data.readUInt16(at: offset + 2))
        return (((first & 0x7FFF) << 16) | second, 4)
    }
}

private extension Data {
    func readUInt8(at offset: Int) -> UInt8 {
        self[offset]
    }

    func readUInt16(at offset: Int) -> UInt16 {
        let value = withUnsafeBytes { rawBuffer -> UInt16 in
            rawBuffer.load(fromByteOffset: offset, as: UInt16.self)
        }
        return UInt16(littleEndian: value)
    }

    func readUInt32(at offset: Int) -> UInt32 {
        let value = withUnsafeBytes { rawBuffer -> UInt32 in
            rawBuffer.load(fromByteOffset: offset, as: UInt32.self)
        }
        return UInt32(littleEndian: value)
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        guard indices.contains(index) else { return nil }
        return self[index]
    }
}
