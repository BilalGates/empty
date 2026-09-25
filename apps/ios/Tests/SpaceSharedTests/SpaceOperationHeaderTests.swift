import CryptoKit
import Foundation
import XCTest
@testable import SpaceShared

final class SpaceOperationHeaderTests: XCTestCase {
    func testMatchesSharedVectorAndExactArtifactHash() throws {
        let vector = try loadVector()
        let header = try makeHeader(vector)
        let encoded = try header.encoded()
        XCTAssertEqual(encoded.hex, vector.headerHex)
        XCTAssertEqual(try SpaceOperationHeader.decode(encoded), header)
        let artifactURL = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "vault-object-envelope-v1", withExtension: "json"))
        let artifact = try JSONDecoder().decode(ArtifactVector.self, from: Data(contentsOf: artifactURL))
        XCTAssertEqual(Data(SHA256.hash(data: try Data(hex: artifact.artifactHex))).hex, vector.ciphertextHashHex)
    }

    func testGenesisAndInvalidParents() throws {
        let vector = try loadVector()
        let value = try makeHeader(vector)
        let genesis = SpaceOperationHeader(
            vaultID: value.vaultID, epoch: value.epoch, opID: value.opID,
            deviceID: value.deviceID, deviceSeq: value.deviceSeq, parentHeads: [],
            objectID: value.objectID, objectVersion: value.objectVersion,
            ciphertextHash: value.ciphertextHash
        )
        XCTAssertEqual(try SpaceOperationHeader.decode(genesis.encoded()), genesis)
        let backwards = SpaceOperationHeader(
            vaultID: value.vaultID, epoch: value.epoch, opID: value.opID,
            deviceID: value.deviceID, deviceSeq: value.deviceSeq,
            parentHeads: Array(value.parentHeads.reversed()), objectID: value.objectID,
            objectVersion: value.objectVersion, ciphertextHash: value.ciphertextHash
        )
        XCTAssertThrowsError(try backwards.encoded())
        let duplicate = SpaceOperationHeader(
            vaultID: value.vaultID, epoch: value.epoch, opID: value.opID,
            deviceID: value.deviceID, deviceSeq: value.deviceSeq,
            parentHeads: [value.parentHeads[0], value.parentHeads[0]], objectID: value.objectID,
            objectVersion: value.objectVersion, ciphertextHash: value.ciphertextHash
        )
        XCTAssertThrowsError(try duplicate.encoded())
    }

    func testRejectsWrongFieldsAndTrailingBytes() throws {
        let vector = try loadVector()
        let value = try makeHeader(vector)
        var bytes = try value.encoded()
        bytes.append(0)
        XCTAssertThrowsError(try SpaceOperationHeader.decode(bytes))
        var wrongSuite = try value.encoded()
        wrongSuite[2] ^= 1
        XCTAssertThrowsError(try SpaceOperationHeader.decode(wrongSuite))
        let wrongHash = SpaceOperationHeader(
            vaultID: value.vaultID, epoch: value.epoch, opID: value.opID,
            deviceID: value.deviceID, deviceSeq: value.deviceSeq,
            parentHeads: value.parentHeads, objectID: value.objectID,
            objectVersion: value.objectVersion, ciphertextHash: Data(repeating: 0, count: 31)
        )
        XCTAssertThrowsError(try wrongHash.encoded())
    }

    private func loadVector() throws -> Vector {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "operation-header-v1", withExtension: "json"))
        return try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
    }

    private func makeHeader(_ vector: Vector) throws -> SpaceOperationHeader {
        try SpaceOperationHeader(
            vaultID: Data(hex: vector.vaultIdHex), epoch: vector.epoch,
            opID: Data(hex: vector.opIdHex), deviceID: Data(hex: vector.deviceIdHex),
            deviceSeq: vector.deviceSeq, parentHeads: vector.parentHeadsHex.map { try Data(hex: $0) },
            objectID: Data(hex: vector.objectIdHex), objectVersion: vector.objectVersion,
            ciphertextHash: Data(hex: vector.ciphertextHashHex)
        )
    }

    private struct Vector: Decodable {
        let vaultIdHex: String
        let epoch: Int
        let opIdHex: String
        let deviceIdHex: String
        let deviceSeq: Int
        let parentHeadsHex: [String]
        let objectIdHex: String
        let objectVersion: Int
        let ciphertextHashHex: String
        let headerHex: String
    }
    private struct ArtifactVector: Decodable { let artifactHex: String }
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else { throw SpaceOperationHeader.Error.invalidHeader }
        var result = Data()
        var cursor = hex.startIndex
        while cursor < hex.endIndex {
            let next = hex.index(cursor, offsetBy: 2)
            guard let byte = UInt8(hex[cursor..<next], radix: 16) else {
                throw SpaceOperationHeader.Error.invalidHeader
            }
            result.append(byte)
            cursor = next
        }
        self = result
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
