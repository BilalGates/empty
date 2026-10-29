import Foundation
import XCTest
@testable import SpaceShared

final class SpaceSignedOperationTests: XCTestCase {
    func testVerifiesSharedOpenSSLVector() throws {
        let fixture = try loadFixture()
        let verified = try SpaceSignedOperation.verify(
            artifact: fixture.artifact, devicePublicKey: fixture.publicKey,
            objectArtifact: fixture.objectArtifact, expected: fixture.context
        )
        XCTAssertEqual(verified.headerBytes.hex, fixture.headerHex)
        XCTAssertEqual(try verified.header.encoded().hex, fixture.headerHex)
    }

    func testRejectsEverySingleByteMutationAndTruncation() throws {
        let fixture = try loadFixture()
        for index in 0..<fixture.artifact.count {
            var mutated = fixture.artifact
            mutated[index] ^= 0x01
            XCTAssertThrowsError(try SpaceSignedOperation.verify(
                artifact: mutated, devicePublicKey: fixture.publicKey,
                objectArtifact: fixture.objectArtifact, expected: fixture.context
            ), "byte \(index)")
        }
        for artifact in [fixture.artifact + Data([0]), fixture.artifact.dropLast()] {
            XCTAssertThrowsError(try SpaceSignedOperation.verify(
                artifact: Data(artifact), devicePublicKey: fixture.publicKey,
                objectArtifact: fixture.objectArtifact, expected: fixture.context
            ))
        }
    }

    func testRejectsOtherObjectContextOrKey() throws {
        let fixture = try loadFixture()
        var otherObject = fixture.objectArtifact
        otherObject[otherObject.count - 1] ^= 0x01
        XCTAssertThrowsError(try SpaceSignedOperation.verify(
            artifact: fixture.artifact, devicePublicKey: fixture.publicKey,
            objectArtifact: otherObject, expected: fixture.context
        ))
        let current = fixture.context
        let wrongVersion = SpaceVaultObjectContext(
            vaultID: current.vaultID, objectID: current.objectID, objectType: current.objectType,
            objectVersion: current.objectVersion + 1, epoch: current.epoch,
            keyID: current.keyID, createdByDevice: current.createdByDevice
        )
        XCTAssertThrowsError(try SpaceSignedOperation.verify(
            artifact: fixture.artifact, devicePublicKey: fixture.publicKey,
            objectArtifact: fixture.objectArtifact, expected: wrongVersion
        ))
        let identityKey = Data([1] + [UInt8](repeating: 0, count: 31))
        for key in [identityKey, fixture.publicKey.dropFirst(), Data(repeating: 0x42, count: 32)] {
            XCTAssertThrowsError(try SpaceSignedOperation.verify(
                artifact: fixture.artifact, devicePublicKey: Data(key),
                objectArtifact: fixture.objectArtifact, expected: fixture.context
            ))
        }
    }

    func testRejectsSharedSmallOrderAndMixedOrderVectors() throws {
        let fixture = try loadFixture()
        XCTAssertEqual(fixture.negativeCases.map(\.name), ["small-order-R", "mixed-order-public-key"])
        let header = try Data(hex: fixture.headerHex)
        XCTAssertEqual(header.count, 176)
        for entry in fixture.negativeCases {
            var artifact = Data("SPCE".utf8) + Data([0, 1, 2])
            var body = Data([0xa2, 0x01, 0x58, UInt8(header.count)]) + header
            body += Data([0x02, 0x58, 0x40]) + (try Data(hex: entry.signatureHex))
            artifact += withUnsafeBytes(of: UInt32(body.count).bigEndian) { Data($0) } + body
            XCTAssertThrowsError(try SpaceSignedOperation.verify(
                artifact: artifact, devicePublicKey: try Data(hex: entry.publicKeyHex),
                objectArtifact: fixture.objectArtifact, expected: fixture.context
            ), entry.name)
        }
    }

    private func loadFixture() throws -> Fixture {
        let bundle = Bundle(for: Self.self)
        func load<T: Decodable>(_ name: String) throws -> T {
            let url = try XCTUnwrap(bundle.url(forResource: name, withExtension: "json"))
            return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
        }
        let operation: OperationVector = try load("signed-operation-v1")
        let envelope: EnvelopeVector = try load("vault-object-envelope-v1")
        let aad: AadVector = try load("vault-object-aad-v1")
        return Fixture(
            artifact: try Data(hex: operation.artifactHex),
            publicKey: try Data(hex: operation.publicKeyHex),
            headerHex: operation.headerHex,
            negativeCases: operation.negativeCases,
            objectArtifact: try Data(hex: envelope.artifactHex),
            context: SpaceVaultObjectContext(
                vaultID: try Data(hex: aad.vaultIdHex), objectID: try Data(hex: aad.objectIdHex),
                objectType: try XCTUnwrap(SpaceVaultObjectAAD.ObjectType(rawValue: aad.objectType)),
                objectVersion: aad.objectVersion, epoch: aad.epoch,
                keyID: try Data(hex: aad.keyIdHex), createdByDevice: try Data(hex: aad.createdByDeviceHex)
            )
        )
    }

    private struct Fixture {
        let artifact: Data
        let publicKey: Data
        let headerHex: String
        let negativeCases: [NegativeCase]
        let objectArtifact: Data
        let context: SpaceVaultObjectContext
    }
    private struct OperationVector: Decodable {
        let artifactHex: String
        let publicKeyHex: String
        let headerHex: String
        let negativeCases: [NegativeCase]
    }
    private struct NegativeCase: Decodable { let name: String; let publicKeyHex: String; let signatureHex: String }
    private struct EnvelopeVector: Decodable { let artifactHex: String }
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
