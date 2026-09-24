import Foundation
import XCTest
@testable import SpaceShared

final class SpaceVaultObjectEnvelopeTests: XCTestCase {
    func testOpensIndependentArtifactVector() throws {
        let fixture = try loadFixture()
        let plaintext = try SpaceVaultObjectEnvelope.open(
            artifact: fixture.artifact,
            vrk: fixture.vrk,
            expected: fixture.context
        )
        XCTAssertEqual(plaintext.hex, fixture.payloadHex)
    }

    func testRejectsEverySingleByteMutation() throws {
        let fixture = try loadFixture()
        for index in 0..<fixture.artifact.count {
            var changed = fixture.artifact
            changed[index] ^= 1
            XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
                artifact: changed,
                vrk: fixture.vrk,
                expected: fixture.context
            ), "byte \(index)") { error in
                XCTAssertEqual(error as? SpaceVaultObjectEnvelope.Error, .invalidEnvelope)
            }
        }
    }

    func testRejectsContextSubstitutionAndMalformedFraming() throws {
        let fixture = try loadFixture()
        let current = fixture.context
        let wrongObject = SpaceVaultObjectContext(
            vaultID: current.vaultID,
            objectID: Data(repeating: 0xff, count: 16),
            objectType: current.objectType,
            objectVersion: current.objectVersion,
            epoch: current.epoch,
            keyID: current.keyID,
            createdByDevice: current.createdByDevice
        )
        XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
            artifact: fixture.artifact, vrk: fixture.vrk, expected: wrongObject
        ))
        let wrongEpoch = SpaceVaultObjectContext(
            vaultID: current.vaultID, objectID: current.objectID,
            objectType: current.objectType, objectVersion: current.objectVersion,
            epoch: current.epoch + 1, keyID: current.keyID,
            createdByDevice: current.createdByDevice
        )
        XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
            artifact: fixture.artifact, vrk: fixture.vrk, expected: wrongEpoch
        ))
        var wrongKey = fixture.vrk
        wrongKey[0] ^= 1
        XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
            artifact: fixture.artifact, vrk: wrongKey, expected: current
        ))
        XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
            artifact: fixture.artifact + Data([0]), vrk: fixture.vrk, expected: current
        ))
        var oversized = fixture.artifact
        oversized.replaceSubrange(7..<11, with: [0xff, 0xff, 0xff, 0xff])
        XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
            artifact: oversized, vrk: fixture.vrk, expected: current
        ))
        var noncanonicalLength = fixture.artifact
        noncanonicalLength.replaceSubrange(13..<15, with: [0x59, 0x00, 0x74])
        noncanonicalLength[10] += 1
        XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
            artifact: noncanonicalLength, vrk: fixture.vrk, expected: current
        ))
    }

    func testRejectsAuthenticatedNoncanonicalPayload() throws {
        let fixture = try loadFixture()
        let envelope = try loadEnvelopeVector()
        var malformed = try Data(hex: envelope.payloadCborHex)
        malformed[0] = 0xa1 // valid prefix with trailing data
        let suite = try SpaceVaultPrimitiveSuite()
        let ciphertext = try suite.seal(
            plaintext: malformed,
            key: Data(hex: envelope.dekHex),
            nonce: Data(hex: envelope.payloadNonceHex),
            authenticatedData: Data(hex: envelope.aadHex) + Data([0]) + Data("payload".utf8)
        )
        var artifact = fixture.artifact
        artifact.replaceSubrange((artifact.count - ciphertext.count)..<artifact.count, with: ciphertext)
        XCTAssertThrowsError(try SpaceVaultObjectEnvelope.open(
            artifact: artifact, vrk: fixture.vrk, expected: fixture.context
        )) { error in
            XCTAssertEqual(error as? SpaceVaultObjectEnvelope.Error, .invalidEnvelope)
        }
    }

    func testDeterministicCBORValidatorRejectsMalformedCorpus() throws {
        for hex in ["1801", "a201010102", "a202000100", "b8010102", "5a00100001", "61ff", "f90000", "9f01ff", "c0f6", "3b001fffffffffffff"] {
            XCTAssertThrowsError(try SpaceDeterministicCBOR.validate(Data(hex: hex)), hex)
        }
        var deeplyNested = Data([0xf6])
        for _ in 0..<17 { deeplyNested = Data([0xa1, 0x01]) + deeplyNested }
        XCTAssertThrowsError(try SpaceDeterministicCBOR.validate(deeplyNested))
        try SpaceDeterministicCBOR.validate(Data(hex: "a201676669787475726502182a"))
    }

    private func loadFixture() throws -> Fixture {
        let bundle = Bundle(for: Self.self)
        let aadURL = try XCTUnwrap(bundle.url(forResource: "vault-object-aad-v1", withExtension: "json"))
        let envelope = try loadEnvelopeVector()
        let aad = try JSONDecoder().decode(AadVector.self, from: Data(contentsOf: aadURL))
        let objectType = try XCTUnwrap(SpaceVaultObjectAAD.ObjectType(rawValue: aad.objectType))
        return Fixture(
            artifact: try Data(hex: envelope.artifactHex),
            vrk: try Data(hex: envelope.vrkHex),
            payloadHex: envelope.payloadCborHex,
            context: SpaceVaultObjectContext(
                vaultID: try Data(hex: aad.vaultIdHex),
                objectID: try Data(hex: aad.objectIdHex),
                objectType: objectType,
                objectVersion: aad.objectVersion,
                epoch: aad.epoch,
                keyID: try Data(hex: aad.keyIdHex),
                createdByDevice: try Data(hex: aad.createdByDeviceHex)
            )
        )
    }

    private func loadEnvelopeVector() throws -> EnvelopeVector {
        let bundle = Bundle(for: Self.self)
        let url = try XCTUnwrap(bundle.url(forResource: "vault-object-envelope-v1", withExtension: "json"))
        return try JSONDecoder().decode(EnvelopeVector.self, from: Data(contentsOf: url))
    }

    private struct Fixture {
        let artifact: Data
        let vrk: Data
        let payloadHex: String
        let context: SpaceVaultObjectContext
    }
    private struct EnvelopeVector: Decodable {
        let artifactHex: String
        let vrkHex: String
        let payloadCborHex: String
        let aadHex: String
        let dekHex: String
        let payloadNonceHex: String
    }
    private struct AadVector: Decodable {
        let vaultIdHex: String
        let objectIdHex: String
        let objectType: String
        let objectVersion: Int
        let epoch: Int
        let keyIdHex: String
        let createdByDeviceHex: String
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
