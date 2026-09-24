import Foundation
import XCTest
@testable import SpaceShared

final class SpaceVaultObjectAADTests: XCTestCase {
    func testMatchesSharedVector() throws {
        let bundle = Bundle(for: Self.self)
        for name in ["vault-object-aad-v1", "vault-object-aad-small-boundary-v1", "vault-object-aad-large-boundary-v1"] {
            let url = try XCTUnwrap(bundle.url(forResource: name, withExtension: "json"))
            let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
            let objectType = try XCTUnwrap(SpaceVaultObjectAAD.ObjectType(rawValue: vector.objectType))
            let encoded = try SpaceVaultObjectAAD.encode(
                vaultID: try data(vector.vaultIdHex),
                objectID: try data(vector.objectIdHex),
                objectType: objectType,
                objectVersion: vector.objectVersion,
                epoch: vector.epoch,
                keyID: try data(vector.keyIdHex),
                createdByDevice: try data(vector.createdByDeviceHex)
            )
            XCTAssertEqual(encoded.map { String(format: "%02x", $0) }.joined(), vector.aadHex, name)
        }
    }

    func testRejectsInvalidContext() throws {
        let id = Data(repeating: 0, count: 16)
        XCTAssertThrowsError(try SpaceVaultObjectAAD.encode(
            vaultID: Data(), objectID: id, objectType: .password,
            objectVersion: 1, epoch: 1, keyID: id, createdByDevice: id
        ))
        XCTAssertThrowsError(try SpaceVaultObjectAAD.encode(
            vaultID: id, objectID: id, objectType: .password,
            objectVersion: 0, epoch: 1, keyID: id, createdByDevice: id
        ))
    }

    private func data(_ hex: String) throws -> Data {
        guard hex.count.isMultiple(of: 2) else { throw ParseError.invalidHex }
        var result = Data()
        var cursor = hex.startIndex
        while cursor < hex.endIndex {
            let next = hex.index(cursor, offsetBy: 2)
            guard let byte = UInt8(hex[cursor..<next], radix: 16) else { throw ParseError.invalidHex }
            result.append(byte)
            cursor = next
        }
        return result
    }

    private enum ParseError: Error { case invalidHex }
    private struct Vector: Decodable {
        let vaultIdHex: String
        let objectIdHex: String
        let objectType: String
        let objectVersion: Int
        let epoch: Int
        let keyIdHex: String
        let createdByDeviceHex: String
        let aadHex: String
    }
}
