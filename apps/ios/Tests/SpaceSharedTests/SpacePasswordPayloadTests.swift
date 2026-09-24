import Foundation
import XCTest
@testable import SpaceShared

final class SpacePasswordPayloadTests: XCTestCase {
    func testDecodesSharedVector() throws {
        let payload = try SpacePasswordPayload.decode(try vectorBytes())
        XCTAssertEqual(payload.title, "Example")
        XCTAssertEqual(payload.origins, ["https://example.com"])
        XCTAssertEqual(payload.username, "alice")
        XCTAssertEqual(payload.password, "demo-only")
        XCTAssertEqual(payload.groupID, Data((0..<16).map(UInt8.init)))
        XCTAssertEqual(payload.notes, "")
        XCTAssertFalse(payload.favorite)
        XCTAssertEqual(payload.createdAtMs, 1_700_000_000_000)
        XCTAssertEqual(payload.updatedAtMs, 1_700_000_000_001)
    }

    func testRejectsMissingUnknownAndWrongTypeFields() throws {
        let bytes = try vectorBytes()
        var missing = bytes
        missing[0] = 0xa8
        XCTAssertThrowsError(try SpacePasswordPayload.decode(missing))
        var wrongTitleType = bytes
        wrongTitleType[2] = 0x47 // byte string instead of text
        XCTAssertThrowsError(try SpacePasswordPayload.decode(wrongTitleType))
        var invalidFavorite = bytes
        let favoriteOffset = try XCTUnwrap(bytes.firstIndex(of: 0xf4))
        invalidFavorite[favoriteOffset] = 0xf6
        XCTAssertThrowsError(try SpacePasswordPayload.decode(invalidFavorite))
        var unknown = bytes
        unknown[0] = 0xaa
        unknown.append(contentsOf: [0x0a, 0xf6])
        XCTAssertThrowsError(try SpacePasswordPayload.decode(unknown))
    }

    private func vectorBytes() throws -> Data {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "password-payload-v1", withExtension: "json"))
        let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
        guard vector.cborHex.count.isMultiple(of: 2) else { throw SpacePasswordPayload.Error.invalidPayload }
        var result = Data()
        var cursor = vector.cborHex.startIndex
        while cursor < vector.cborHex.endIndex {
            let next = vector.cborHex.index(cursor, offsetBy: 2)
            guard let byte = UInt8(vector.cborHex[cursor..<next], radix: 16) else {
                throw SpacePasswordPayload.Error.invalidPayload
            }
            result.append(byte)
            cursor = next
        }
        return result
    }

    private struct Vector: Decodable { let cborHex: String }
}
