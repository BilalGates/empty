import Clibsodium
import CryptoKit
import Foundation

/// Verifies a framed V1 signed operation against a trusted device key and the exact object artifact.
/// The caller still owns revocation, monotonic device sequence, DAG ancestry and checkpoints.
public enum SpaceSignedOperation {
    public enum Error: Swift.Error, Equatable { case invalidOperation }

    private static let maximumArtifactBytes = 32 * 1_024
    private static let maximumHeaderBytes = 16 * 1_024
    private static let sodiumReady: Bool = sodium_init() >= 0

    public struct Verified: Equatable, Sendable {
        public let header: SpaceOperationHeader
        /// Exact signed bytes; persist these instead of re-encoding the header.
        public let headerBytes: Data
    }

    public static func verify(
        artifact: Data,
        devicePublicKey: Data,
        objectArtifact: Data,
        expected: SpaceVaultObjectContext
    ) throws -> Verified {
        do {
            guard sodiumReady, devicePublicKey.count == Int(crypto_sign_publickeybytes()) else {
                throw Error.invalidOperation
            }
            let (headerBytes, signature) = try parse(artifact)
            // libsodium rejects small-order keys and non-canonical S during verification.
            let valid = signature.withUnsafeBytes { sig in
                headerBytes.withUnsafeBytes { message in
                    devicePublicKey.withUnsafeBytes { key in
                        crypto_sign_verify_detached(
                            sig.bindMemory(to: UInt8.self).baseAddress!,
                            message.bindMemory(to: UInt8.self).baseAddress,
                            UInt64(headerBytes.count),
                            key.bindMemory(to: UInt8.self).baseAddress!
                        )
                    }
                }
            }
            guard valid == 0 else { throw Error.invalidOperation }
            let header = try SpaceOperationHeader.decode(headerBytes)
            let record = try SpaceVaultObjectEnvelope.parse(objectArtifact)
            guard sameBytes(record.aad, try expected.encodedAAD()),
                  sameBytes(Data(SHA256.hash(data: objectArtifact)), header.ciphertextHash),
                  sameBytes(header.vaultID, expected.vaultID), header.epoch == expected.epoch,
                  sameBytes(header.objectID, expected.objectID),
                  header.objectVersion == expected.objectVersion,
                  sameBytes(header.deviceID, expected.createdByDevice) else { throw Error.invalidOperation }
            return Verified(header: header, headerBytes: headerBytes)
        } catch {
            throw Error.invalidOperation
        }
    }

    /// `SPCE || 0x0001 || kind 2 || u32 length || {1: header_cbor, 2: signature(64)}`.
    private static func parse(_ artifact: Data) throws -> (Data, Data) {
        let bytes = [UInt8](artifact)
        guard bytes.count >= 12, bytes.count <= maximumArtifactBytes,
              Array(bytes[0..<7]) == [0x53, 0x50, 0x43, 0x45, 0, 1, 2] else { throw Error.invalidOperation }
        let length = bytes[7..<11].reduce(0) { $0 * 256 + Int($1) }
        guard length == bytes.count - 11 else { throw Error.invalidOperation }
        var offset = 11
        func expect(_ value: UInt8) throws {
            guard offset < bytes.count, bytes[offset] == value else { throw Error.invalidOperation }
            offset += 1
        }
        func byteString(maximum: Int) throws -> Data {
            guard offset < bytes.count, bytes[offset] >> 5 == 2 else { throw Error.invalidOperation }
            let additional = Int(bytes[offset] & 31)
            offset += 1
            let count: Int
            switch additional {
            case 0..<24: count = additional
            case 24:
                guard offset < bytes.count, bytes[offset] >= 24 else { throw Error.invalidOperation }
                count = Int(bytes[offset]); offset += 1
            case 25:
                guard offset + 2 <= bytes.count else { throw Error.invalidOperation }
                count = Int(bytes[offset]) * 256 + Int(bytes[offset + 1]); offset += 2
                guard count >= 256 else { throw Error.invalidOperation }
            default: throw Error.invalidOperation
            }
            guard count <= maximum, count <= bytes.count - offset else { throw Error.invalidOperation }
            defer { offset += count }
            return Data(bytes[offset..<(offset + count)])
        }
        try expect(0xa2)
        try expect(1)
        let header = try byteString(maximum: maximumHeaderBytes)
        try expect(2)
        let signature = try byteString(maximum: 64)
        guard signature.count == 64, offset == bytes.count else { throw Error.invalidOperation }
        return (header, signature)
    }

    private static func sameBytes(_ left: Data, _ right: Data) -> Bool {
        var difference = left.count ^ right.count
        let l = [UInt8](left), r = [UInt8](right)
        for index in 0..<max(l.count, r.count) {
            difference |= Int((index < l.count ? l[index] : 0) ^ (index < r.count ? r[index] : 0))
        }
        return difference == 0
    }
}
