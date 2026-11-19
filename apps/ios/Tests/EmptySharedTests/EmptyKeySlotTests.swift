import Foundation
import XCTest
@testable import EmptyShared

final class EmptyKeySlotTests: XCTestCase {
    func testReproducesIndependentAADKEKAndCiphertext() throws {
        let v = try loadVector()
        let suite = try EmptyVaultPrimitiveSuite()
        let passwordAAD = try EmptyKeySlot.encodeAAD(.password, context: v.passwordContext, salt: try Data(hex: v.password.saltHex!))
        XCTAssertEqual(passwordAAD.hex, v.password.aadHex)
        let passwordKEK = try suite.derivePasswordKEK(
            argonOutput: try Data(hex: v.password.argonOutputHex!), vaultID: v.vaultID, slotID: v.passwordContext.slotID)
        XCTAssertEqual(passwordKEK.hex, v.password.kekHex)
        let recoveryAAD = try EmptyKeySlot.encodeAAD(.recovery, context: v.recoveryContext, salt: nil)
        XCTAssertEqual(recoveryAAD.hex, v.recovery.aadHex)
        let recoveryKEK = try suite.deriveRecoveryKEK(
            recoverySecret: try Data(hex: v.recovery.secretHex!), vaultID: v.vaultID, slotID: v.recoveryContext.slotID)
        XCTAssertEqual(recoveryKEK.hex, v.recovery.kekHex)
        for (slot, aad, kek) in [(v.password, passwordAAD, passwordKEK), (v.recovery, recoveryAAD, recoveryKEK)] {
            let ciphertext = try suite.seal(plaintext: v.vrk, key: kek, nonce: try Data(hex: slot.nonceHex), authenticatedData: aad)
            XCTAssertEqual(ciphertext.hex, slot.ciphertextHex)
        }
    }

    func testOpensVectorPasswordSlotAndRejectsWrongPassword() throws {
        let v = try loadVector()
        let password = try XCTUnwrap(String(data: try Data(hex: v.password.passwordUtf8Hex!), encoding: .utf8))
        let artifact = try Data(hex: v.password.artifactHex)
        XCTAssertEqual(try EmptyKeySlot.openPassword(artifact: artifact, context: v.passwordContext, password: password), v.vrk)
        XCTAssertThrowsError(try EmptyKeySlot.openPassword(artifact: artifact, context: v.passwordContext, password: password + "!"))
    }

    func testPasswordRoundTripIsNFCInsensitiveAndFresh() throws {
        let v = try loadVector()
        let composed = "contraseña-Ünïcode-2026"
        let decomposed = composed.decomposedStringWithCanonicalMapping
        XCTAssertNotEqual(Array(composed.utf8), Array(decomposed.utf8))
        let sealed = try EmptyKeySlot.sealPassword(vrk: v.vrk, context: v.passwordContext, password: composed)
        XCTAssertEqual(try EmptyKeySlot.openPassword(artifact: sealed, context: v.passwordContext, password: decomposed), v.vrk)
        XCTAssertNotEqual(try EmptyKeySlot.sealPassword(vrk: v.vrk, context: v.passwordContext, password: composed), sealed)
    }

    func testRecoverySlotOpenRoundTripAndContextBinding() throws {
        let v = try loadVector()
        let artifact = try Data(hex: v.recovery.artifactHex)
        XCTAssertEqual(try EmptyKeySlot.encodeRecoveryKey(try Data(hex: v.recovery.secretHex!)), v.recovery.encoded)
        XCTAssertEqual(try EmptyKeySlot.openRecovery(artifact: artifact, context: v.recoveryContext, encodedRecoveryKey: v.recovery.encoded!), v.vrk)
        let relaxed = v.recovery.encoded!.lowercased().replacingOccurrences(of: "-", with: " ")
        XCTAssertEqual(try EmptyKeySlot.openRecovery(artifact: artifact, context: v.recoveryContext, encodedRecoveryKey: relaxed), v.vrk)
        let secret = Data((0..<32).map { UInt8(255 - $0) })
        let sealed = try EmptyKeySlot.sealRecovery(vrk: v.vrk, context: v.recoveryContext, secret: secret)
        XCTAssertEqual(try EmptyKeySlot.openRecovery(
            artifact: sealed, context: v.recoveryContext, encodedRecoveryKey: try EmptyKeySlot.encodeRecoveryKey(secret)), v.vrk)
        let wrong = [
            EmptyKeySlot.Context(vaultID: v.vaultID, slotID: v.recoveryContext.slotID, epoch: 2),
            EmptyKeySlot.Context(vaultID: v.vaultID, slotID: v.passwordContext.slotID, epoch: 1),
            EmptyKeySlot.Context(vaultID: Data(count: 16), slotID: v.recoveryContext.slotID, epoch: 1)
        ]
        for context in wrong {
            XCTAssertThrowsError(try EmptyKeySlot.openRecovery(artifact: artifact, context: context, encodedRecoveryKey: v.recovery.encoded!))
        }
        XCTAssertThrowsError(try EmptyKeySlot.openRecovery(
            artifact: try Data(hex: v.password.artifactHex), context: v.passwordContext, encodedRecoveryKey: v.recovery.encoded!))
        for index in 0..<artifact.count {
            var mutated = artifact
            mutated[index] ^= 0x01
            XCTAssertThrowsError(try EmptyKeySlot.openRecovery(
                artifact: mutated, context: v.recoveryContext, encodedRecoveryKey: v.recovery.encoded!), "byte \(index)")
        }
    }

    func testRejectsSharedInvalidRecoveryEncodings() throws {
        let v = try loadVector()
        for encoded in v.invalidRecoveryEncodings {
            XCTAssertThrowsError(try EmptyKeySlot.decodeRecoveryKey(encoded), encoded)
        }
        for (name, artifactHex) in v.invalidArtifactsHex {
            XCTAssertThrowsError(try EmptyKeySlot.openRecovery(
                artifact: try Data(hex: artifactHex), context: v.recoveryContext,
                encodedRecoveryKey: v.recovery.encoded!), name)
        }
    }

    // MARK: Fixture

    private struct Vector: Decodable {
        struct Slot: Decodable {
            let slotIdHex: String
            let kekHex: String
            let nonceHex: String
            let aadHex: String
            let ciphertextHex: String
            let artifactHex: String
            let passwordUtf8Hex: String?
            let saltHex: String?
            let argonOutputHex: String?
            let secretHex: String?
            let encoded: String?
        }
        let vaultIdHex: String
        let vrkHex: String
        let epoch: Int
        let password: Slot
        let recovery: Slot
        let invalidRecoveryEncodings: [String]
        let invalidArtifactsHex: [String: String]
    }

    private struct Loaded {
        let vaultID: Data
        let vrk: Data
        let password: Vector.Slot
        let recovery: Vector.Slot
        let passwordContext: EmptyKeySlot.Context
        let recoveryContext: EmptyKeySlot.Context
        let invalidRecoveryEncodings: [String]
        let invalidArtifactsHex: [String: String]
    }

    private func loadVector() throws -> Loaded {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "key-slot-v1", withExtension: "json"))
        let v = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
        let vaultID = try Data(hex: v.vaultIdHex)
        return Loaded(
            vaultID: vaultID, vrk: try Data(hex: v.vrkHex), password: v.password, recovery: v.recovery,
            passwordContext: .init(vaultID: vaultID, slotID: try Data(hex: v.password.slotIdHex), epoch: v.epoch),
            recoveryContext: .init(vaultID: vaultID, slotID: try Data(hex: v.recovery.slotIdHex), epoch: v.epoch),
            invalidRecoveryEncodings: v.invalidRecoveryEncodings,
            invalidArtifactsHex: v.invalidArtifactsHex
        )
    }
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else { throw HexError.invalid }
        var result = Data()
        var cursor = hex.startIndex
        while cursor < hex.endIndex {
            let next = hex.index(cursor, offsetBy: 2)
            guard let byte = UInt8(hex[cursor..<next], radix: 16) else { throw HexError.invalid }
            result.append(byte)
            cursor = next
        }
        self = result
    }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    enum HexError: Error { case invalid }
}
