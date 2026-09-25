import Foundation
import XCTest
@testable import SpaceShared

final class SpacePasswordOriginTests: XCTestCase {
    func testSharedOriginCorpus() throws {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "password-origins-v1", withExtension: "json"))
        let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
        for origin in vector.valid { XCTAssertTrue(SpacePasswordOrigin.isCanonical(origin), origin) }
        for origin in vector.invalid { XCTAssertFalse(SpacePasswordOrigin.isCanonical(origin), origin) }
    }

    private struct Vector: Decodable {
        let valid: [String]
        let invalid: [String]
    }
}
