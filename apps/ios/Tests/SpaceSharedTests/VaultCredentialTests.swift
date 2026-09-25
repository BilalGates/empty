import XCTest
@testable import SpaceShared

final class VaultCredentialTests: XCTestCase {
    func testCanonicalServiceIdentifierAcceptsHTTPSAndLoopbackOnly() {
        XCTAssertEqual(
            VaultCredential.canonicalServiceIdentifier("Example.COM/login"),
            "https://example.com"
        )
        XCTAssertEqual(
            VaultCredential.canonicalServiceIdentifier("http://localhost:8080/login"),
            "http://localhost:8080"
        )
        XCTAssertNil(VaultCredential.canonicalServiceIdentifier("http://example.com"))
        XCTAssertNil(VaultCredential.canonicalServiceIdentifier("https://user:pass@example.com"))
    }

    func testAutofillPolicyMatchesOnlyCompleteOrigin() {
        let credential = VaultCredential(
            title: "Example",
            serviceIdentifier: "https://Example.com/login",
            username: "person@example.com",
            password: "test-value"
        )
        let url = SpaceAutofillOriginPolicy.Service(identifier: "https://example.com/account", kind: .url)
        XCTAssertTrue(SpaceAutofillOriginPolicy.matches(credential, service: url))
        for identifier in ["http://example.com", "https://example.com:8443", "https://notexample.com", "https://login.example.com"] {
            XCTAssertFalse(SpaceAutofillOriginPolicy.matches(
                credential, service: .init(identifier: identifier, kind: .url)
            ), identifier)
        }
        XCTAssertFalse(SpaceAutofillOriginPolicy.matches(
            credential, service: .init(identifier: "example.com", kind: .domain)
        ))
        XCTAssertFalse(SpaceAutofillOriginPolicy.matches(
            credential, service: .init(identifier: "com.example.app", kind: .app)
        ))
        XCTAssertEqual(SpaceAutofillOriginPolicy.matching([credential], services: []), [])
    }

    func testIdentityDescriptorNeverContainsPassword() {
        let credential = VaultCredential(
            title: "Title",
            serviceIdentifier: "example.com",
            username: "username",
            password: "password-value"
        )
        let descriptor = CredentialIdentityDescriptor(credential: credential)
        XCTAssertFalse(String(reflecting: descriptor).contains("password-value"))
        XCTAssertEqual(descriptor.recordIdentifier, credential.id.uuidString)
    }
}
