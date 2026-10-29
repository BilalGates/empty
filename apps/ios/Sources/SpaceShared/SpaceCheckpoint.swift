import CryptoKit
import Foundation

/// Local V1 anti-rollback checkpoint, authenticated with HMAC-SHA-256 under the Checkpoint MAC Key.
/// It detects rollback against this device's prior state; DAG ancestry is still the caller's job.
public struct SpaceCheckpoint: Equatable, Sendable {
    public struct DeviceSequence: Equatable, Sendable {
        public let deviceID: Data
        public let deviceSeq: Int
        public init(deviceID: Data, deviceSeq: Int) {
            self.deviceID = deviceID
            self.deviceSeq = deviceSeq
        }
    }

    public let vaultID: Data
    public let epoch: Int
    public let heads: [Data]
    public let deviceSeqs: [DeviceSequence]

    public enum Error: Swift.Error, Equatable { case invalidCheckpoint }
    private static let maximumBytes = 16 * 1_024
    private static let maximumArtifactBytes = 32 * 1_024
    private static let maximumInteger = 9_007_199_254_740_991

    public init(vaultID: Data, epoch: Int, heads: [Data], deviceSeqs: [DeviceSequence]) {
        self.vaultID = vaultID
        self.epoch = epoch
        self.heads = heads
        self.deviceSeqs = deviceSeqs
    }

    private func validate() throws {
        guard vaultID.count == 16, epoch > 0, epoch <= Self.maximumInteger,
              (1...64).contains(heads.count), heads.allSatisfy({ $0.count == 16 }),
              (1...64).contains(deviceSeqs.count),
              deviceSeqs.allSatisfy({ $0.deviceID.count == 16 && $0.deviceSeq > 0 && $0.deviceSeq <= Self.maximumInteger }),
              Self.strictlySorted(heads), Self.strictlySorted(deviceSeqs.map(\.deviceID)) else {
            throw Error.invalidCheckpoint
        }
    }

    private static func strictlySorted(_ values: [Data]) -> Bool {
        zip(values, values.dropFirst()).allSatisfy { $0.lexicographicallyPrecedes($1) }
    }

    public func encoded() throws -> Data {
        do {
            try validate()
            var output = Data([0xa6]) // six exact integer-keyed map entries
            output.append(1); Self.appendText("space.vault/1", to: &output)
            output.append(2); Self.appendText("checkpoint", to: &output)
            output.append(3); Self.appendBytes(vaultID, to: &output)
            output.append(4); Self.appendHeader(major: 0, value: UInt64(epoch), to: &output)
            output.append(5); Self.appendHeader(major: 4, value: UInt64(heads.count), to: &output)
            for head in heads { Self.appendBytes(head, to: &output) }
            output.append(6); Self.appendHeader(major: 4, value: UInt64(deviceSeqs.count), to: &output)
            for entry in deviceSeqs {
                output.append(0x82)
                Self.appendBytes(entry.deviceID, to: &output)
                Self.appendHeader(major: 0, value: UInt64(entry.deviceSeq), to: &output)
            }
            guard output.count <= Self.maximumBytes else { throw Error.invalidCheckpoint }
            return output
        } catch { throw Error.invalidCheckpoint }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        do {
            guard bytes.count <= maximumBytes else { throw Error.invalidCheckpoint }
            try SpaceDeterministicCBOR.validate(bytes, maximumBytes: maximumBytes)
            var reader = Reader(bytes: [UInt8](bytes))
            try reader.expect(0xa6)
            try reader.expect(1); try reader.expectText("space.vault/1")
            try reader.expect(2); try reader.expectText("checkpoint")
            try reader.expect(3); let vaultID = try reader.byteString(count: 16)
            try reader.expect(4); let epoch = try reader.argument(major: 0)
            try reader.expect(5)
            let headCount = try reader.argument(major: 4)
            guard headCount <= 64 else { throw Error.invalidCheckpoint }
            var heads = [Data]()
            for _ in 0..<headCount { heads.append(try reader.byteString(count: 16)) }
            try reader.expect(6)
            let deviceCount = try reader.argument(major: 4)
            guard deviceCount <= 64 else { throw Error.invalidCheckpoint }
            var deviceSeqs = [DeviceSequence]()
            for _ in 0..<deviceCount {
                try reader.expect(0x82)
                let deviceID = try reader.byteString(count: 16)
                deviceSeqs.append(DeviceSequence(deviceID: deviceID, deviceSeq: try reader.argument(major: 0)))
            }
            guard reader.isAtEnd else { throw Error.invalidCheckpoint }
            let result = Self(vaultID: vaultID, epoch: epoch, heads: heads, deviceSeqs: deviceSeqs)
            try result.validate()
            return result
        } catch { throw Error.invalidCheckpoint }
    }

    // MARK: Sealed artifact: SPCE || 0x0001 || kind 3 || u32 length || {1: checkpoint_cbor, 2: mac(32)}

    public func sealed(vrk: Data) throws -> Data {
        do {
            let body = try encoded()
            let key = SymmetricKey(data: try SpaceVaultPrimitiveSuite().deriveCheckpointKey(vrk: vrk, vaultID: vaultID))
            var record = Data([0xa2, 0x01])
            Self.appendBytes(body, to: &record)
            record.append(0x02)
            Self.appendBytes(Data(HMAC<SHA256>.authenticationCode(for: body, using: key)), to: &record)
            var artifact = Data([0x53, 0x50, 0x43, 0x45, 0, 1, 3])
            artifact.append(contentsOf: withUnsafeBytes(of: UInt32(record.count).bigEndian, Array.init))
            return artifact + record
        } catch { throw Error.invalidCheckpoint }
    }

    /// Verifies the MAC under the trusted vault ID before parsing the checkpoint body.
    public static func open(artifact: Data, vrk: Data, expectedVaultID: Data) throws -> Self {
        do {
            guard expectedVaultID.count == 16 else { throw Error.invalidCheckpoint }
            let (body, mac) = try parse(artifact)
            let key = SymmetricKey(data: try SpaceVaultPrimitiveSuite().deriveCheckpointKey(vrk: vrk, vaultID: expectedVaultID))
            guard HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: body, using: key) else {
                throw Error.invalidCheckpoint
            }
            let checkpoint = try decode(body)
            guard checkpoint.vaultID == expectedVaultID else { throw Error.invalidCheckpoint }
            return checkpoint
        } catch { throw Error.invalidCheckpoint }
    }

    /// Necessary (not sufficient) rollback check: same vault, epoch never lowered, and no device
    /// sequence forgotten or lowered. DAG ancestry of `next.heads` must still be proven separately.
    public func cannotBeRolledBack(to next: SpaceCheckpoint) -> Bool {
        // Fail closed on unvalidated input; validation also guarantees unique device IDs below.
        guard (try? validate()) != nil, (try? next.validate()) != nil,
              vaultID == next.vaultID, next.epoch >= epoch else { return false }
        let latest = Dictionary(uniqueKeysWithValues: next.deviceSeqs.map { ($0.deviceID, $0.deviceSeq) })
        return deviceSeqs.allSatisfy { entry in (latest[entry.deviceID] ?? 0) >= entry.deviceSeq }
    }

    private static func parse(_ artifact: Data) throws -> (Data, Data) {
        let bytes = [UInt8](artifact)
        guard bytes.count >= 12, bytes.count <= maximumArtifactBytes,
              Array(bytes[0..<7]) == [0x53, 0x50, 0x43, 0x45, 0, 1, 3] else { throw Error.invalidCheckpoint }
        guard bytes[7..<11].reduce(0, { $0 * 256 + Int($1) }) == bytes.count - 11 else { throw Error.invalidCheckpoint }
        var reader = Reader(bytes: bytes, offset: 11)
        try reader.expect(0xa2)
        try reader.expect(1)
        let bodyLength = try reader.argument(major: 2)
        guard bodyLength <= maximumBytes else { throw Error.invalidCheckpoint }
        let body = try reader.take(bodyLength)
        try reader.expect(2)
        let mac = try reader.byteString(count: 32)
        guard reader.isAtEnd else { throw Error.invalidCheckpoint }
        return (body, mac)
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

    /// Minimal-length (deterministic) CBOR argument reader over a bounded byte array.
    private struct Reader {
        let bytes: [UInt8]
        var offset = 0
        var isAtEnd: Bool { offset == bytes.count }

        mutating func byte() throws -> UInt8 {
            guard offset < bytes.count else { throw Error.invalidCheckpoint }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func expect(_ value: UInt8) throws {
            guard try byte() == value else { throw Error.invalidCheckpoint }
        }

        mutating func argument(major: UInt8) throws -> Int {
            let initial = try byte()
            guard initial >> 5 == major else { throw Error.invalidCheckpoint }
            let additional = initial & 31
            if additional < 24 { return Int(additional) }
            let width: Int
            let minimum: UInt64
            switch additional {
            case 24: width = 1; minimum = 24
            case 25: width = 2; minimum = 0x100
            case 26: width = 4; minimum = 0x1_0000
            case 27: width = 8; minimum = 0x1_0000_0000
            default: throw Error.invalidCheckpoint
            }
            var value: UInt64 = 0
            for _ in 0..<width { value = value * 256 + UInt64(try byte()) }
            guard value >= minimum, value <= UInt64(SpaceCheckpoint.maximumInteger) else { throw Error.invalidCheckpoint }
            return Int(value)
        }

        mutating func take(_ count: Int) throws -> Data {
            guard count <= bytes.count - offset else { throw Error.invalidCheckpoint }
            defer { offset += count }
            return Data(bytes[offset..<(offset + count)])
        }

        mutating func byteString(count: Int) throws -> Data {
            guard try argument(major: 2) == count else { throw Error.invalidCheckpoint }
            return try take(count)
        }

        mutating func expectText(_ value: String) throws {
            let expected = Data(value.utf8)
            guard try argument(major: 3) == expected.count, try take(expected.count) == expected else {
                throw Error.invalidCheckpoint
            }
        }
    }
}
