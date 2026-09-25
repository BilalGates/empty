import AuthenticationServices
import XCTest
import SpaceShared

final class CredentialProviderTests: XCTestCase {
    func testFilterUsesExactNormalizedHost() {
        let expected = VaultCredential(
            title: "Expected",
            serviceIdentifier: "https://example.com/login",
            username: "a",
            password: "one"
        )
        let lookalike = VaultCredential(
            title: "Lookalike",
            serviceIdentifier: "https://notexample.com",
            username: "b",
            password: "two"
        )
        let service = ASCredentialServiceIdentifier(identifier: "example.com", type: .domain)
        XCTAssertEqual(
            VaultCredential.matching([expected, lookalike], serviceIdentifiers: [service.identifier]),
            [expected]
        )
    }
}
