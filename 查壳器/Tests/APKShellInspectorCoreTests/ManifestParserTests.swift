import Foundation
import Testing
@testable import APKShellInspectorCore

@Test("parses package and sdk values from a binary manifest fixture")
func parsesManifestFixture() throws {
    let data = ManifestFixtureBuilder.makeManifest()

    let parsed = try BinaryAndroidManifestParser().parse(data: data, fileName: "fixture.apk")

    #expect(parsed.fileName == "fixture.apk")
    #expect(parsed.packageName == "com.demo.shell")
    #expect(parsed.versionName == "1.2.3")
    #expect(parsed.versionCode == "12")
    #expect(parsed.minSDK == "24")
    #expect(parsed.targetSDK == "34")
}

@Test("parses package and sdk values from a manifest with real-world chunk layout")
func parsesManifestWithRealWorldChunkLayout() throws {
    let data = ManifestFixtureBuilder.makeRealWorldLikeManifest()

    let parsed = try BinaryAndroidManifestParser().parse(data: data, fileName: "real.apk")

    #expect(parsed.fileName == "real.apk")
    #expect(parsed.packageName == "com.demo.real")
    #expect(parsed.versionName == "5.2.1-rc19")
    #expect(parsed.versionCode == "50201")
    #expect(parsed.minSDK == "21")
    #expect(parsed.targetSDK == "30")
}

private enum ManifestFixtureBuilder {
    private static let xmlType: UInt16 = 0x0003
    private static let stringPoolType: UInt16 = 0x0001
    private static let startNamespaceType: UInt16 = 0x0100
    private static let startElementType: UInt16 = 0x0102
    private static let resourceMapType: UInt16 = 0x0180
    private static let stringType: UInt8 = 0x03
    private static let intType: UInt8 = 0x10

    static func makeManifest() -> Data {
        let strings = [
            "manifest",
            "package",
            "com.demo.shell",
            "versionName",
            "1.2.3",
            "versionCode",
            "uses-sdk",
            "minSdkVersion",
            "targetSdkVersion",
        ]
        let pool = makeStringPool(strings)

        let manifestChunk = makeStartElement(
            nameIndex: 0,
            attributes: [
                stringAttribute(nameIndex: 1, valueIndex: 2),
                stringAttribute(nameIndex: 3, valueIndex: 4),
                intAttribute(nameIndex: 5, value: 12),
            ]
        )
        let usesSDKChunk = makeStartElement(
            nameIndex: 6,
            attributes: [
                intAttribute(nameIndex: 7, value: 24),
                intAttribute(nameIndex: 8, value: 34),
            ]
        )

        var xml = Data()
        xml.appendLE(UInt16(0x0003))
        xml.appendLE(UInt16(8))
        xml.appendLE(UInt32(8 + pool.count + manifestChunk.count + usesSDKChunk.count))
        xml.append(pool)
        xml.append(manifestChunk)
        xml.append(usesSDKChunk)
        return xml
    }

    static func makeRealWorldLikeManifest() -> Data {
        let strings = [
            "android",
            "http://schemas.android.com/apk/res/android",
            "manifest",
            "package",
            "com.demo.real",
            "versionName",
            "5.2.1-rc19",
            "versionCode",
            "uses-sdk",
            "minSdkVersion",
            "targetSdkVersion",
        ]

        let pool = makeStringPool(strings)
        let resourceMap = makeResourceMap([0x0101_0003, 0x0101_021c, 0x0101_0270, 0x0101_0271])
        let namespace = makeNamespaceChunk(prefixIndex: 0, uriIndex: 1)
        let manifestChunk = makeStartElement(
            nameIndex: 2,
            namespaceIndex: UInt32.max,
            attributes: [
                stringAttribute(namespaceIndex: UInt32.max, nameIndex: 3, valueIndex: 4),
                stringAttribute(namespaceIndex: 1, nameIndex: 5, valueIndex: 6),
                intAttribute(namespaceIndex: 1, nameIndex: 7, value: 50_201),
            ]
        )
        let usesSDKChunk = makeStartElement(
            nameIndex: 8,
            namespaceIndex: UInt32.max,
            attributes: [
                intAttribute(namespaceIndex: 1, nameIndex: 9, value: 21),
                intAttribute(namespaceIndex: 1, nameIndex: 10, value: 30),
            ]
        )

        let xmlHeaderSize = 12
        let totalSize = xmlHeaderSize + pool.count + resourceMap.count + namespace.count + manifestChunk.count + usesSDKChunk.count

        var xml = Data()
        xml.appendLE(xmlType)
        xml.appendLE(UInt16(xmlHeaderSize))
        xml.appendLE(UInt32(totalSize))
        xml.appendLE(UInt32(0))
        xml.append(pool)
        xml.append(resourceMap)
        xml.append(namespace)
        xml.append(manifestChunk)
        xml.append(usesSDKChunk)
        return xml
    }

    private static func makeStringPool(_ strings: [String]) -> Data {
        var stringData = Data()
        var offsets: [UInt32] = []

        for value in strings {
            offsets.append(UInt32(stringData.count))
            let utf8 = Array(value.utf8)
            stringData.append(UInt8(utf8.count))
            stringData.append(UInt8(utf8.count))
            stringData.append(contentsOf: utf8)
            stringData.append(0)
        }

        while stringData.count % 4 != 0 {
            stringData.append(0)
        }

        let headerSize = 28
        let stringsStart = headerSize + offsets.count * 4
        let chunkSize = stringsStart + stringData.count

        var data = Data()
        data.appendLE(stringPoolType)
        data.appendLE(UInt16(headerSize))
        data.appendLE(UInt32(chunkSize))
        data.appendLE(UInt32(strings.count))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x100))
        data.appendLE(UInt32(stringsStart))
        data.appendLE(UInt32(0))
        offsets.forEach { data.appendLE($0) }
        data.append(stringData)
        return data
    }

    private static func makeResourceMap(_ values: [UInt32]) -> Data {
        var data = Data()
        data.appendLE(resourceMapType)
        data.appendLE(UInt16(8))
        data.appendLE(UInt32(8 + values.count * 4))
        values.forEach { data.appendLE($0) }
        return data
    }

    private static func makeNamespaceChunk(prefixIndex: UInt32, uriIndex: UInt32) -> Data {
        var data = Data()
        data.appendLE(startNamespaceType)
        data.appendLE(UInt16(16))
        data.appendLE(UInt32(24))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(UInt32.max))
        data.appendLE(prefixIndex)
        data.appendLE(uriIndex)
        return data
    }

    private static func makeStartElement(
        nameIndex: UInt32,
        namespaceIndex: UInt32 = UInt32.max,
        attributes: [Attribute]
    ) -> Data {
        let headerSize = 36
        let attributeSize = 20
        let chunkSize = headerSize + attributes.count * attributeSize

        var data = Data()
        data.appendLE(startElementType)
        data.appendLE(UInt16(headerSize))
        data.appendLE(UInt32(chunkSize))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0xFFFF_FFFF))
        data.appendLE(namespaceIndex)
        data.appendLE(nameIndex)
        data.appendLE(UInt16(20))
        data.appendLE(UInt16(attributeSize))
        data.appendLE(UInt16(attributes.count))
        data.appendLE(UInt16(0))
        data.appendLE(UInt16(0))
        data.appendLE(UInt16(0))

        for attribute in attributes {
            data.appendLE(attribute.namespaceIndex)
            data.appendLE(attribute.nameIndex)
            data.appendLE(attribute.rawValueIndex)
            data.appendLE(UInt16(8))
            data.append(UInt8(0))
            data.append(attribute.type)
            data.appendLE(attribute.data)
        }
        return data
    }

    private static func stringAttribute(
        namespaceIndex: UInt32 = UInt32.max,
        nameIndex: UInt32,
        valueIndex: UInt32
    ) -> Attribute {
        Attribute(
            namespaceIndex: namespaceIndex,
            nameIndex: nameIndex,
            rawValueIndex: valueIndex,
            type: stringType,
            data: valueIndex
        )
    }

    private static func intAttribute(
        namespaceIndex: UInt32 = UInt32.max,
        nameIndex: UInt32,
        value: UInt32
    ) -> Attribute {
        Attribute(
            namespaceIndex: namespaceIndex,
            nameIndex: nameIndex,
            rawValueIndex: 0xFFFF_FFFF,
            type: intType,
            data: value
        )
    }

    private struct Attribute {
        let namespaceIndex: UInt32
        let nameIndex: UInt32
        let rawValueIndex: UInt32
        let type: UInt8
        let data: UInt32
    }
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var little = value.littleEndian
        Swift.withUnsafeBytes(of: &little) { append(contentsOf: $0) }
    }
}
