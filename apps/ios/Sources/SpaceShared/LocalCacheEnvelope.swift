import CryptoKit
import Foundation

/// A local-only cache format. It is not the interoperable `space.vault/1` format.
public enum LocalCacheEnvelope {
    public static let formatIdentifier = "space.ios.local-cache/1"
    public static let maximumEnvelopeSize = 16 * 1_024 * 1_024
    private static let magic = Data([0x53, 0x50, 0x43, 0x49]) // SPCi
    private static let version: UInt16 = 1
    private static let headerSize = 4 + 2 + 16
    private static let nonceSize = 12
    private static let tagSize = 16
    public static let minimumEnvelopeSize = headerSize + nonceSize + tagSize
    public static let maximumPlaintextSize = maximumEnvelopeSize - minimumEnvelopeSize

    public enum EnvelopeError: Error, Equatable {
        case invalidEnvelope
        case oversized
    }

    public static func seal(
        _ plaintext: Data,
        vaultID: UUID,
        key: SymmetricKey
    ) throws -> Data {
        guard plaintext.count <= maximumPlaintextSize else { throw EnvelopeError.oversized }
        let header = makeHeader(vaultID: vaultID)
        // CryptoKit obtains a fresh random 96-bit nonce when nonce is omitted.
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: header)
        guard let combined = box.combined else { throw EnvelopeError.invalidEnvelope }
        let result = header + combined
        guard result.count <= maximumEnvelopeSize else { throw EnvelopeError.oversized }
        return result
    }

    public static func open(
        _ envelope: Data,
        expectedVaultID: UUID,
        key: SymmetricKey
    ) throws -> Data {
        guard envelope.count <= maximumEnvelopeSize else { throw EnvelopeError.oversized }
        guard envelope.count >= minimumEnvelopeSize else { throw EnvelopeError.invalidEnvelope }
        let header = envelope.prefix(headerSize)
        guard header == makeHeader(vaultID: expectedVaultID) else {
            throw EnvelopeError.invalidEnvelope
        }
        do {
            let box = try AES.GCM.SealedBox(combined: Data(envelope.dropFirst(headerSize)))
            return try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            // Do not expose whether framing, vault binding, or authentication failed.
            throw EnvelopeError.invalidEnvelope
        }
    }

    private static func makeHeader(vaultID: UUID) -> Data {
        var header = magic
        header.append(UInt8(version >> 8))
        header.append(UInt8(version & 0xff))
        var uuid = vaultID.uuid
        withUnsafeBytes(of: &uuid) { header.append(contentsOf: $0) }
        return header
    }
}
