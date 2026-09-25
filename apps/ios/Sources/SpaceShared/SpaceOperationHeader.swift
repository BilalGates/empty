import Foundation

/// Deterministic V1 bytes that a device will sign. Parsing alone does not verify a signature.
public struct SpaceOperationHeader: Equatable, Sendable {
    public let vaultID: Data
    public let epoch: Int
    public let opID: Data
    public let deviceID: Data
    public let deviceSeq: Int
    public let parentHeads: [Data]
    public let objectID: Data
    public let objectVersion: Int
    public let ciphertextHash: Data

    public enum Error: Swift.Error, Equatable { case invalidHeader }
    private static let maximumBytes = 16 * 1_024
    private static let maximumInteger = 9_007_199_254_740_991

    public init(
        vaultID: Data, epoch: Int, opID: Data, deviceID: Data, deviceSeq: Int,
        parentHeads: [Data], objectID: Data, objectVersion: Int, ciphertextHash: Data
    ) {
        self.vaultID = vaultID
        self.epoch = epoch
        self.opID = opID
        self.deviceID = deviceID
        self.deviceSeq = deviceSeq
        self.parentHeads = parentHeads
        self.objectID = objectID
        self.objectVersion = objectVersion
        self.ciphertextHash = ciphertextHash
    }

    private func validate() throws {
        guard vaultID.count == 16, opID.count == 16, deviceID.count == 16,
              objectID.count == 16, ciphertextHash.count == 32,
              epoch > 0, deviceSeq > 0, objectVersion > 0,
              epoch <= Self.maximumInteger, deviceSeq <= Self.maximumInteger,
              objectVersion <= Self.maximumInteger, parentHeads.count <= 64,
              parentHeads.allSatisfy({ $0.count == 16 }) else { throw Error.invalidHeader }
        if parentHeads.count > 1 {
            for index in 1..<parentHeads.count {
                guard parentHeads[index - 1].lexicographicallyPrecedes(parentHeads[index]) else {
                    throw Error.invalidHeader
                }
            }
        }
    }

    public func encoded() throws -> Data {
        do {
            try validate()
            var output = Data([0xab]) // eleven exact integer-keyed map entries
            output.append(1); Self.appendText("space.vault/1", to: &output)
            output.append(2); Self.appendText("operation", to: &output)
            output.append(3); Self.appendBytes(vaultID, to: &output)
            output.append(4); Self.appendHeader(major: 0, value: UInt64(epoch), to: &output)
            output.append(5); Self.appendBytes(opID, to: &output)
            output.append(6); Self.appendBytes(deviceID, to: &output)
            output.append(7); Self.appendHeader(major: 0, value: UInt64(deviceSeq), to: &output)
            output.append(8); Self.appendHeader(major: 4, value: UInt64(parentHeads.count), to: &output)
            for parent in parentHeads { Self.appendBytes(parent, to: &output) }
            output.append(9); Self.appendBytes(objectID, to: &output)
            output.append(10); Self.appendHeader(major: 0, value: UInt64(objectVersion), to: &output)
            output.append(11); Self.appendBytes(ciphertextHash, to: &output)
            guard output.count <= Self.maximumBytes else { throw Error.invalidHeader }
            return output
        } catch { throw Error.invalidHeader }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        do {
            guard bytes.count <= maximumBytes else { throw Error.invalidHeader }
            try SpaceDeterministicCBOR.validate(bytes, maximumBytes: maximumBytes)
            var reader = Reader(bytes: bytes)
            try reader.expect(0xab)
            try reader.expect(1); try reader.expectText("space.vault/1")
            try reader.expect(2); try reader.expectText("operation")
            try reader.expect(3); let vaultID = try reader.byteString(count: 16)
            try reader.expect(4); let epoch = try reader.positiveInteger()
            try reader.expect(5); let opID = try reader.byteString(count: 16)
            try reader.expect(6); let deviceID = try reader.byteString(count: 16)
            try reader.expect(7); let deviceSeq = try reader.positiveInteger()
            try reader.expect(8)
            let parentCount = try reader.argument(major: 4)
            guard parentCount <= 64 else { throw Error.invalidHeader }
            var parents = [Data]()
            for _ in 0..<parentCount { parents.append(try reader.byteString(count: 16)) }
            try reader.expect(9); let objectID = try reader.byteString(count: 16)
            try reader.expect(10); let objectVersion = try reader.positiveInteger()
            try reader.expect(11); let ciphertextHash = try reader.byteString(count: 32)
            guard reader.isAtEnd else { throw Error.invalidHeader }
            let result = Self(
                vaultID: vaultID, epoch: epoch, opID: opID, deviceID: deviceID,
                deviceSeq: deviceSeq, parentHeads: parents, objectID: objectID,
                objectVersion: objectVersion, ciphertextHash: ciphertextHash
            )
            try result.validate()
            return result
        } catch { throw Error.invalidHeader }
    }

    private static func appendText(_ value: String, to output: inout Data) {
        let bytes = Data(value.utf8)
        appendHeader(major: 3, value: UInt64(bytes.count), to: &output)
        output.append(bytes)
    }

    private static func appendBytes(_ value: Data, to output: inout Data) {
        appendHeader(major: 2, value: UInt64(value.count), to: &output)
        output.append(value)
    }

    private static func appendHeader(major: UInt8, value: UInt64, to output: inout Data) {
        let prefix = major << 5
        if value < 24 {
            output.append(prefix | UInt8(value))
        } else if value <= UInt64(UInt8.max) {
            output.append(contentsOf: [prefix | 24, UInt8(value)])
        } else if value <= UInt64(UInt16.max) {
            output.append(prefix | 25)
            output.append(contentsOf: withUnsafeBytes(of: UInt16(value).bigEndian, Array.init))
        } else if value <= UInt64(UInt32.max) {
            output.append(prefix | 26)
            output.append(contentsOf: withUnsafeBytes(of: UInt32(value).bigEndian, Array.init))
        } else {
            output.append(prefix | 27)
            output.append(contentsOf: withUnsafeBytes(of: value.bigEndian, Array.init))
        }
    }

    private struct Reader {
        let bytes: Data
        private(set) var offset = 0
        var isAtEnd: Bool { offset == bytes.count }

        mutating func byte() throws -> UInt8 {
            guard offset < bytes.count else { throw Error.invalidHeader }
            defer { offset += 1 }
            return bytes[bytes.index(bytes.startIndex, offsetBy: offset)]
        }

        mutating func expect(_ value: UInt8) throws {
            guard try byte() == value else { throw Error.invalidHeader }
        }

        mutating func argument(major: UInt8) throws -> Int {
            let initial = try byte()
            guard initial >> 5 == major else { throw Error.invalidHeader }
            let additional = initial & 31
            if additional < 24 { return Int(additional) }
            let width: Int
            switch additional {
            case 24: width = 1
            case 25: width = 2
            case 26: width = 4
            case 27: width = 8
            default: throw Error.invalidHeader
            }
            var value: UInt64 = 0
            for _ in 0..<width { value = value * 256 + UInt64(try byte()) }
            guard value <= UInt64(SpaceOperationHeader.maximumInteger) else { throw Error.invalidHeader }
            return Int(value)
        }

        mutating func byteString(count: Int) throws -> Data {
            guard try argument(major: 2) == count, count <= bytes.count - offset else { throw Error.invalidHeader }
            let start = bytes.index(bytes.startIndex, offsetBy: offset)
            offset += count
            let end = bytes.index(bytes.startIndex, offsetBy: offset)
            return bytes.subdata(in: start..<end)
        }

        mutating func expectText(_ value: String) throws {
            let expected = Data(value.utf8)
            guard try argument(major: 3) == expected.count,
                  expected.count <= bytes.count - offset else { throw Error.invalidHeader }
            let start = bytes.index(bytes.startIndex, offsetBy: offset)
            offset += expected.count
            let end = bytes.index(bytes.startIndex, offsetBy: offset)
            guard bytes.subdata(in: start..<end) == expected else { throw Error.invalidHeader }
        }

        mutating func positiveInteger() throws -> Int {
            let value = try argument(major: 0)
            guard value > 0 else { throw Error.invalidHeader }
            return value
        }
    }
}
