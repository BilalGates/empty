import CryptoKit
import Foundation

/// V1 password and recovery key slots: `SPCE || 0x0001 || kind 4 || u32 length ||
/// {1: aad_bytes, 2: nonce(24), 3: XChaCha20-Poly1305(KEK, nonce, VRK, aad_bytes)(48)}`.
public enum SpaceKeySlot {
    public enum Error: Swift.Error, Equatable { case invalidKeySlot }
    public enum SlotType: String, Sendable { case password, recovery }

    /// Trusted routing context supplied by the caller; artifact fields never substitute for it.
    public struct Context: Sendable {
        public let vaultID: Data
        public let slotID: Data
        public let epoch: Int
        public init(vaultID: Data, slotID: Data, epoch: Int) {
            self.vaultID = vaultID
            self.slotID = slotID
            self.epoch = epoch
        }
    }

    private static let maximumArtifactBytes = 32 * 1_024
    private static let maximumInteger = 9_007_199_254_740_991
    private static let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    // MARK: Password slot (host app only: Argon2id at the fixed V1 cost)

    public static func sealPassword(vrk: Data, context: Context, password: String) throws -> Data {
        var kek: Data?
        defer { wipe(&kek) }
        do {
            let suite = try SpaceVaultPrimitiveSuite()
            let salt = try suite.randomKey().prefix(16)
            kek = try passwordKEK(suite: suite, password: password, salt: Data(salt), context: context)
            let aad = try encodeAAD(.password, context: context, salt: Data(salt))
            return try seal(suite: suite, kek: kek!, aad: aad, vrk: vrk)
        } catch { throw Error.invalidKeySlot }
    }

    /// Single external error for wrong password, tampering, or context mismatch.
    public static func openPassword(artifact: Data, context: Context, password: String) throws -> Data {
        var kek: Data?
        defer { wipe(&kek) }
        do {
            let record = try parse(artifact)
            let salt = try passwordSalt(in: record.aad)
            guard sameBytes(record.aad, try encodeAAD(.password, context: context, salt: salt)) else {
                throw Error.invalidKeySlot
            }
            let suite = try SpaceVaultPrimitiveSuite()
            kek = try passwordKEK(suite: suite, password: password, salt: salt, context: context)
            return try open(suite: suite, kek: kek!, record: record)
        } catch { throw Error.invalidKeySlot }
    }

    // MARK: Recovery slot

    public static func sealRecovery(vrk: Data, context: Context, secret: Data) throws -> Data {
        var kek: Data?
        defer { wipe(&kek) }
        do {
            let suite = try SpaceVaultPrimitiveSuite()
            guard secret.count == 32 else { throw Error.invalidKeySlot }
            kek = try suite.deriveRecoveryKEK(recoverySecret: secret, vaultID: context.vaultID, slotID: context.slotID)
            return try seal(suite: suite, kek: kek!, aad: try encodeAAD(.recovery, context: context, salt: nil), vrk: vrk)
        } catch { throw Error.invalidKeySlot }
    }

    public static func openRecovery(artifact: Data, context: Context, encodedRecoveryKey: String) throws -> Data {
        var kek: Data?
        var secret: Data?
        defer { wipe(&kek); wipe(&secret) }
        do {
            let record = try parse(artifact)
            guard sameBytes(record.aad, try encodeAAD(.recovery, context: context, salt: nil)) else {
                throw Error.invalidKeySlot
            }
            secret = try decodeRecoveryKey(encodedRecoveryKey)
            let suite = try SpaceVaultPrimitiveSuite()
            kek = try suite.deriveRecoveryKEK(recoverySecret: secret!, vaultID: context.vaultID, slotID: context.slotID)
            return try open(suite: suite, kek: kek!, record: record)
        } catch { throw Error.invalidKeySlot }
    }

    // MARK: Recovery key text: 13 groups of four Base32 characters plus a four-character checksum

    public static func encodeRecoveryKey(_ secret: Data) throws -> String {
        guard secret.count == 32 else { throw Error.invalidKeySlot }
        let data = base32([UInt8](secret), characters: 52)
        var groups = stride(from: 0, to: 52, by: 4).map { String(decoding: data[$0..<($0 + 4)], as: UTF8.self) }
        groups.append(String(decoding: checksum(secret), as: UTF8.self))
        return groups.joined(separator: "-")
    }

    /// Accepts any case, spaces and hyphens; rejects wrong length, non-zero pad bits and bad checksum.
    public static func decodeRecoveryKey(_ encoded: String) throws -> Data {
        // ASCII Base32 letters/digits plus space, tab, CR, LF and hyphen only, checked before case folding.
        let raw = Array(encoded.utf8)
        let separators: Set<UInt8> = [0x20, 0x09, 0x0d, 0x0a, 0x2d]
        guard raw.count <= 128, raw.allSatisfy({ separators.contains($0) || (0x61...0x7a).contains($0) ||
                                                   (0x41...0x5a).contains($0) || (0x32...0x37).contains($0) }) else {
            throw Error.invalidKeySlot
        }
        let compact = raw.filter { !separators.contains($0) }.map { (0x61...0x7a).contains($0) ? $0 - 0x20 : $0 }
        guard compact.count == 56 else { throw Error.invalidKeySlot }
        var secret = [UInt8]()
        defer { secret.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var buffer: UInt32 = 0
        var bits = 0
        for character in compact[0..<52] {
            guard let value = base32Alphabet.firstIndex(of: character) else { throw Error.invalidKeySlot }
            buffer = (buffer << 5) | UInt32(value)
            bits += 5
            if bits >= 8 {
                secret.append(UInt8((buffer >> UInt32(bits - 8)) & 0xff))
                bits -= 8
                buffer &= (1 << UInt32(bits)) - 1
            }
        }
        let result = Data(secret)
        guard secret.count == 32, buffer == 0, checksum(result) == Array(compact[52..<56]) else {
            throw Error.invalidKeySlot
        }
        return result
    }

    // MARK: Internals

    private struct Record {
        let aad: Data
        let nonce: Data
        let ciphertext: Data
    }

    private static func passwordKEK(suite: SpaceVaultPrimitiveSuite, password: String, salt: Data, context: Context) throws -> Data {
        var stretched: Data? = try suite.derivePasswordKey(password: password, salt: salt)
        defer { wipe(&stretched) }
        return try suite.derivePasswordKEK(argonOutput: stretched!, vaultID: context.vaultID, slotID: context.slotID)
    }

    private static func seal(suite: SpaceVaultPrimitiveSuite, kek: Data, aad: Data, vrk: Data) throws -> Data {
        guard vrk.count == 32 else { throw Error.invalidKeySlot }
        let nonce = try suite.randomNonce()
        let ciphertext = try suite.seal(plaintext: vrk, key: kek, nonce: nonce, authenticatedData: aad)
        var body = Data([0xa3, 0x01])
        appendBytes(aad, to: &body)
        body.append(0x02); appendBytes(nonce, to: &body)
        body.append(0x03); appendBytes(ciphertext, to: &body)
        var artifact = Data([0x53, 0x50, 0x43, 0x45, 0, 1, 4])
        artifact.append(contentsOf: withUnsafeBytes(of: UInt32(body.count).bigEndian, Array.init))
        return artifact + body
    }

    private static func open(suite: SpaceVaultPrimitiveSuite, kek: Data, record: Record) throws -> Data {
        let vrk = try suite.open(ciphertext: record.ciphertext, key: kek, nonce: record.nonce, authenticatedData: record.aad)
        guard vrk.count == 32 else { throw Error.invalidKeySlot }
        return vrk
    }

    static func encodeAAD(_ type: SlotType, context: Context, salt: Data?) throws -> Data {
        guard context.vaultID.count == 16, context.slotID.count == 16,
              context.epoch > 0, context.epoch <= maximumInteger,
              (type == .password) == (salt?.count == 16), type == .password || salt == nil else {
            throw Error.invalidKeySlot
        }
        var output = Data([type == .password ? 0xa7 : 0xa6])
        output.append(1); appendText("space.vault/1", to: &output)
        output.append(2); appendText("key-slot", to: &output)
        output.append(3); appendText(type.rawValue, to: &output)
        output.append(4); appendBytes(context.vaultID, to: &output)
        output.append(5); appendBytes(context.slotID, to: &output)
        output.append(6); appendUnsigned(UInt64(context.epoch), to: &output)
        if let salt {
            output.append(7)
            output.append(0xa6)
            output.append(1); appendText("argon2id", to: &output)
            output.append(2); appendUnsigned(19, to: &output)
            output.append(3); appendUnsigned(UInt64(SpaceVaultPrimitiveSuite.argonMemoryKiB), to: &output)
            output.append(4); appendUnsigned(UInt64(SpaceVaultPrimitiveSuite.argonIterations), to: &output)
            output.append(5); appendUnsigned(UInt64(SpaceVaultPrimitiveSuite.argonParallelism), to: &output)
            output.append(6); appendBytes(salt, to: &output)
        }
        return output
    }

    /// The salt is the final 16 bytes of an exact V1 password AAD; the caller then requires the
    /// complete AAD to equal one re-encoded from trusted context, so no other field is trusted.
    private static func passwordSalt(in aad: Data) throws -> Data {
        guard aad.count > 17 else { throw Error.invalidKeySlot }
        let bytes = [UInt8](aad)
        guard bytes[bytes.count - 17] == 0x50 else { throw Error.invalidKeySlot }
        return Data(bytes[(bytes.count - 16)...])
    }

    private static func parse(_ artifact: Data) throws -> Record {
        let bytes = [UInt8](artifact)
        guard bytes.count >= 12, bytes.count <= maximumArtifactBytes,
              Array(bytes[0..<7]) == [0x53, 0x50, 0x43, 0x45, 0, 1, 4],
              bytes[7..<11].reduce(0, { $0 * 256 + Int($1) }) == bytes.count - 11 else { throw Error.invalidKeySlot }
        var offset = 11
        func expect(_ value: UInt8) throws {
            guard offset < bytes.count, bytes[offset] == value else { throw Error.invalidKeySlot }
            offset += 1
        }
        func byteString() throws -> Data {
            guard offset < bytes.count, bytes[offset] >> 5 == 2 else { throw Error.invalidKeySlot }
            let additional = Int(bytes[offset] & 31)
            offset += 1
            var count = additional
            if additional == 24 {
                guard offset < bytes.count, bytes[offset] >= 24 else { throw Error.invalidKeySlot }
                count = Int(bytes[offset]); offset += 1
            } else if additional == 25 {
                guard offset + 2 <= bytes.count else { throw Error.invalidKeySlot }
                count = Int(bytes[offset]) * 256 + Int(bytes[offset + 1]); offset += 2
                guard count >= 256 else { throw Error.invalidKeySlot }
            } else if additional > 24 {
                throw Error.invalidKeySlot
            }
            guard count <= bytes.count - offset else { throw Error.invalidKeySlot }
            defer { offset += count }
            return Data(bytes[offset..<(offset + count)])
        }
        try expect(0xa3)
        try expect(1); let aad = try byteString()
        try expect(2); let nonce = try byteString()
        try expect(3); let ciphertext = try byteString()
        guard offset == bytes.count, nonce.count == 24, ciphertext.count == 48 else { throw Error.invalidKeySlot }
        return Record(aad: aad, nonce: nonce, ciphertext: ciphertext)
    }

    private static func base32(_ bytes: [UInt8], characters: Int) -> [UInt8] {
        var output = [UInt8]()
        var buffer: UInt32 = 0
        var bits = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 && output.count < characters {
                output.append(base32Alphabet[Int((buffer >> UInt32(bits - 5)) & 31)])
                bits -= 5
            }
            buffer &= (1 << UInt32(bits)) - 1
        }
        if output.count < characters && bits > 0 {
            output.append(base32Alphabet[Int((buffer << UInt32(5 - bits)) & 31)])
        }
        return Array(output.prefix(characters))
    }

    private static func checksum(_ secret: Data) -> [UInt8] {
        let digest = SHA256.hash(data: Data("space/recovery-check/v1".utf8) + secret)
        return base32(Array(digest.prefix(3)), characters: 4)
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

    private static func appendUnsigned(_ value: UInt64, to output: inout Data) {
        appendHeader(major: 0, value: value, to: &output)
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

    private static func sameBytes(_ left: Data, _ right: Data) -> Bool {
        var difference = left.count ^ right.count
        let l = [UInt8](left), r = [UInt8](right)
        for index in 0..<max(l.count, r.count) {
            difference |= Int((index < l.count ? l[index] : 0) ^ (index < r.count ? r[index] : 0))
        }
        return difference == 0
    }

    private static func wipe(_ value: inout Data?) {
        guard let count = value?.count else { return }
        value?.resetBytes(in: 0..<count)
        value = nil
    }
}
