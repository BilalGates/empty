import Clibsodium
import CryptoKit
import Foundation
import argon2

/// Reviewed primitives for `space.vault/1` interoperability.
///
/// This facade deliberately does not serialize vault records. Callers must supply the
/// exact deterministic-CBOR AAD bytes owned by the protocol layer. Until those codecs
/// and their cross-platform vectors land, this type must not replace LocalCacheEnvelope.
public struct SpaceVaultPrimitiveSuite: Sendable {
    public static let suiteIdentifier = "space.vault/1"
    public static let keySize = 32
    public static let nonceSize = 24
    public static let tagSize = 16
    public static let maximumPlaintextSize = 16 * 1_024 * 1_024
    public static let maximumAuthenticatedDataSize = 16 * 1_024

    public static let passwordSaltSize = 16
    public static let passwordMinimumBytes = 1
    public static let passwordMaximumBytes = 1_024
    public static let argonMemoryKiB: UInt32 = 65_536
    public static let argonIterations: UInt32 = 3
    public static let argonParallelism: UInt32 = 4

    private static let sodiumReady: Bool = sodium_init() >= 0

    public init() throws {
        guard Self.sodiumReady else { throw Error.primitiveUnavailable }
    }

    public enum Error: Swift.Error, Equatable {
        case invalidParameters
        case invalidEnvelope
        case primitiveUnavailable
    }

    /// Runs only in the host app. The AutoFill extension consumes a Keychain-protected
    /// local unlock key and never reduces these normative parameters.
    public func derivePasswordKey(password: String, salt: Data) throws -> Data {
        let normalized = password.precomposedStringWithCanonicalMapping
        var passwordBytes = Array(normalized.utf8)
        defer { Self.wipe(&passwordBytes) }

        guard passwordBytes.count >= Self.passwordMinimumBytes,
              passwordBytes.count <= Self.passwordMaximumBytes,
              salt.count == Self.passwordSaltSize else {
            throw Error.invalidParameters
        }

        let saltBytes = [UInt8](salt)
        var output = [UInt8](repeating: 0, count: Self.keySize)
        defer { Self.wipe(&output) }
        let status = argon2id_hash_raw(
            Self.argonIterations,
            Self.argonMemoryKiB,
            Self.argonParallelism,
            passwordBytes,
            passwordBytes.count,
            saltBytes,
            saltBytes.count,
            &output,
            output.count
        )
        guard status == 0 else {
            throw Error.primitiveUnavailable
        }
        return Data(output)
    }

    public func deriveVaultWrapKey(vrk: Data, vaultID: Data) throws -> Data {
        try hkdf(
            inputKeyMaterial: vrk,
            salt: vaultID,
            info: Data("space/vwk/v1".utf8)
        )
    }

    public func deriveCheckpointKey(vrk: Data, vaultID: Data) throws -> Data {
        try hkdf(
            inputKeyMaterial: vrk,
            salt: vaultID,
            info: Data("space/checkpoint/v1".utf8)
        )
    }

    public func derivePasswordKEK(
        argonOutput: Data,
        vaultID: Data,
        slotID: Data
    ) throws -> Data {
        guard slotID.count == 16 else { throw Error.invalidParameters }
        return try hkdf(
            inputKeyMaterial: argonOutput,
            salt: vaultID,
            info: Data("space/password-kek/v1".utf8) + slotID
        )
    }

    public func randomNonce() throws -> Data {
        guard Self.sodiumReady else { throw Error.primitiveUnavailable }
        var nonce = [UInt8](repeating: 0, count: Self.nonceSize)
        randombytes_buf(&nonce, nonce.count)
        return Data(nonce)
    }

    public func seal(
        plaintext: Data,
        key: Data,
        nonce: Data,
        authenticatedData: Data
    ) throws -> Data {
        guard key.count == Self.keySize, nonce.count == Self.nonceSize else {
            throw Error.invalidParameters
        }
        guard plaintext.count <= Self.maximumPlaintextSize,
              authenticatedData.count <= Self.maximumAuthenticatedDataSize else {
            throw Error.invalidParameters
        }
        var message = [UInt8](plaintext)
        var keyBytes = [UInt8](key)
        defer {
            Self.wipe(&message)
            Self.wipe(&keyBytes)
        }
        let nonceBytes = [UInt8](nonce)
        let aad = [UInt8](authenticatedData)
        var ciphertext = [UInt8](repeating: 0, count: message.count + Self.tagSize)
        var ciphertextLength: UInt64 = 0
        let status = crypto_aead_xchacha20poly1305_ietf_encrypt(
            &ciphertext,
            &ciphertextLength,
            message,
            UInt64(message.count),
            aad,
            UInt64(aad.count),
            nil,
            nonceBytes,
            keyBytes
        )
        guard status == 0, ciphertextLength == UInt64(ciphertext.count) else {
            throw Error.primitiveUnavailable
        }
        return Data(ciphertext)
    }

    public func open(
        ciphertext: Data,
        key: Data,
        nonce: Data,
        authenticatedData: Data
    ) throws -> Data {
        guard key.count == Self.keySize,
              nonce.count == Self.nonceSize,
              ciphertext.count >= Self.tagSize,
              ciphertext.count <= Self.maximumPlaintextSize + Self.tagSize,
              authenticatedData.count <= Self.maximumAuthenticatedDataSize else {
            throw Error.invalidEnvelope
        }
        let ciphertextBytes = [UInt8](ciphertext)
        var keyBytes = [UInt8](key)
        let nonceBytes = [UInt8](nonce)
        let aad = [UInt8](authenticatedData)
        var plaintext = [UInt8](repeating: 0, count: ciphertext.count - Self.tagSize)
        defer {
            Self.wipe(&keyBytes)
            Self.wipe(&plaintext)
        }
        var plaintextLength: UInt64 = 0
        let status = crypto_aead_xchacha20poly1305_ietf_decrypt(
            &plaintext,
            &plaintextLength,
            nil,
            ciphertextBytes,
            UInt64(ciphertextBytes.count),
            aad,
            UInt64(aad.count),
            nonceBytes,
            keyBytes
        )
        guard status == 0, plaintextLength == UInt64(plaintext.count) else {
            throw Error.invalidEnvelope
        }
        return Data(plaintext)
    }

    private func hkdf(
        inputKeyMaterial: Data,
        salt: Data,
        info: Data
    ) throws -> Data {
        guard inputKeyMaterial.count == Self.keySize, salt.count == 16 else {
            throw Error.invalidParameters
        }
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: inputKeyMaterial),
            salt: salt,
            info: info,
            outputByteCount: Self.keySize
        )
        return key.withUnsafeBytes { Data($0) }
    }

    private static func wipe(_ bytes: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        bytes.withUnsafeMutableBytes { buffer in
            sodium_memzero(buffer.baseAddress, buffer.count)
        }
    }
}
