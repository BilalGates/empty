import Foundation
import XCTest
@testable import SpaceShared

final class SpaceCheckpointTests: XCTestCase {
    func testMatchesIndependentPythonVector() throws {
        let fixture = try loadFixture()
        XCTAssertEqual(try SpaceVaultPrimitiveSuite().deriveCheckpointKey(vrk: fixture.vrk, vaultID: fixture.vaultID).hex,
                       fixture.vector.checkpointKeyHex)
        XCTAssertEqual(try fixture.checkpoint.encoded().hex, fixture.vector.checkpointHex)
        XCTAssertEqual(try fixture.checkpoint.sealed(vrk: fixture.vrk).hex, fixture.vector.artifactHex)
        XCTAssertEqual(try SpaceCheckpoint.open(artifact: fixture.artifact, vrk: fixture.vrk, expectedVaultID: fixture.vaultID),
                       fixture.checkpoint)
    }

    func testRejectsMutationTruncationWrongKeyAndWrongVault() throws {
        let fixture = try loadFixture()
        for index in 0..<fixture.artifact.count {
            var mutated = fixture.artifact
            mutated[index] ^= 0x01
            XCTAssertThrowsError(try SpaceCheckpoint.open(artifact: mutated, vrk: fixture.vrk, expectedVaultID: fixture.vaultID),
                                 "byte \(index)")
        }
        XCTAssertThrowsError(try SpaceCheckpoint.open(artifact: fixture.artifact + Data([0]), vrk: fixture.vrk, expectedVaultID: fixture.vaultID))
        XCTAssertThrowsError(try SpaceCheckpoint.open(artifact: fixture.artifact.dropLast(), vrk: fixture.vrk, expectedVaultID: fixture.vaultID))
        XCTAssertThrowsError(try SpaceCheckpoint.open(artifact: fixture.artifact, vrk: Data(count: 32), expectedVaultID: fixture.vaultID))
        XCTAssertThrowsError(try SpaceCheckpoint.open(artifact: fixture.artifact, vrk: fixture.vrk, expectedVaultID: Data(repeating: 9, count: 16)))
    }

    func testRejectsMalformedCheckpoints() throws {
        let value = try loadFixture().checkpoint
        let invalid = [
            SpaceCheckpoint(vaultID: value.vaultID, epoch: value.epoch, heads: [], deviceSeqs: value.deviceSeqs),
            SpaceCheckpoint(vaultID: value.vaultID, epoch: value.epoch, heads: value.heads.reversed(), deviceSeqs: value.deviceSeqs),
            SpaceCheckpoint(vaultID: value.vaultID, epoch: value.epoch, heads: value.heads, deviceSeqs: []),
            SpaceCheckpoint(vaultID: value.vaultID, epoch: value.epoch, heads: value.heads, deviceSeqs: value.deviceSeqs.reversed()),
            SpaceCheckpoint(vaultID: value.vaultID, epoch: 0, heads: value.heads, deviceSeqs: value.deviceSeqs),
            SpaceCheckpoint(vaultID: value.vaultID, epoch: value.epoch, heads: value.heads,
                            deviceSeqs: [.init(deviceID: Data(count: 16), deviceSeq: 0)])
        ]
        for checkpoint in invalid { XCTAssertThrowsError(try checkpoint.encoded()) }
    }

    func testRollbackDetection() throws {
        let value = try loadFixture().checkpoint
        let first = value.deviceSeqs[0], second = value.deviceSeqs[1]
        let advanced = SpaceCheckpoint(
            vaultID: value.vaultID, epoch: 2, heads: value.heads,
            deviceSeqs: [.init(deviceID: first.deviceID, deviceSeq: 3), .init(deviceID: Data(repeating: 0x50, count: 16), deviceSeq: 1), second]
        )
        XCTAssertTrue(value.cannotBeRolledBack(to: value))
        XCTAssertTrue(value.cannotBeRolledBack(to: advanced))
        XCTAssertFalse(advanced.cannotBeRolledBack(to: value))
        XCTAssertFalse(value.cannotBeRolledBack(to: SpaceCheckpoint(
            vaultID: value.vaultID, epoch: 1, heads: value.heads, deviceSeqs: [second])))
        XCTAssertFalse(value.cannotBeRolledBack(to: SpaceCheckpoint(
            vaultID: Data(repeating: 9, count: 16), epoch: 1, heads: value.heads, deviceSeqs: value.deviceSeqs)))
        // Duplicate device IDs in a hand-built checkpoint must fail closed, not crash.
        XCTAssertFalse(value.cannotBeRolledBack(to: SpaceCheckpoint(
            vaultID: value.vaultID, epoch: 1, heads: value.heads, deviceSeqs: [first, first, second])))
    }

    private func loadFixture() throws -> Fixture {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "checkpoint-v1", withExtension: "json"))
        let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
        let vaultID = try Data(hex: vector.vaultIdHex)
        return Fixture(
            vector: vector, vrk: try Data(hex: vector.vrkHex), vaultID: vaultID,
            artifact: try Data(hex: vector.artifactHex),
            checkpoint: SpaceCheckpoint(
                vaultID: vaultID, epoch: vector.epoch, heads: try vector.headsHex.map { try Data(hex: $0) },
                deviceSeqs: try vector.deviceSeqs.map { .init(deviceID: try Data(hex: $0.deviceIdHex), deviceSeq: $0.deviceSeq) }
            )
        )
    }

    private struct Fixture {
        let vector: Vector
        let vrk: Data
        let vaultID: Data
        let artifact: Data
        let checkpoint: SpaceCheckpoint
    }
    private struct Vector: Decodable {
        struct Entry: Decodable { let deviceIdHex: String; let deviceSeq: Int }
        let vrkHex: String
        let vaultIdHex: String
        let epoch: Int
        let headsHex: [String]
        let deviceSeqs: [Entry]
        let checkpointKeyHex: String
        let checkpointHex: String
        let artifactHex: String
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
