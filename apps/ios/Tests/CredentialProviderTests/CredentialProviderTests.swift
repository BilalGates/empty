import AuthenticationServices
import XCTest
import SpaceShared

final class CredentialProviderTests: XCTestCase {
    func testFilterUsesExactURLOriginAndRejectsDomainOnlyRequest() {
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
        let service = ASCredentialServiceIdentifier(identifier: "https://example.com/account", type: .URL)
        XCTAssertEqual(
            SpaceAutofillOriginPolicy.matching(
                [expected, lookalike], services: [.init(identifier: service.identifier, kind: .url)]
            ),
            [expected]
        )
        XCTAssertEqual(SpaceAutofillOriginPolicy.matching(
            [expected], services: [.init(identifier: "example.com", kind: .domain)]
        ), [])
    }
}
