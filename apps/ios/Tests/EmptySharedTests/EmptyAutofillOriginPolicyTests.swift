import Foundation
import XCTest
@testable import EmptyShared

final class EmptyAutofillOriginPolicyTests: XCTestCase {
    func testAcceptsOnlyCanonicalURLRequestOrigins() {
        let valid: [String: String] = [
            "https://example.com": "https://example.com",
            "https://example.com/login": "https://example.com",
            "https://example.com:8443/path?q=1": "https://example.com:8443",
            "http://localhost:8080/login": "http://localhost:8080"
        ]
        for (identifier, origin) in valid {
            XCTAssertEqual(EmptyAutofillOriginPolicy.requestedOrigin(
                .init(identifier: identifier, kind: .url)
            ), origin, identifier)
        }
        for identifier in [
            "example.com", "https://Example.com", "https://example.com:443/login",
            "http://example.com", "https://user@example.com",
            "https://xn--a.example", "https://example.com:0443", "https://example.com\\@evil.com"
        ] {
            XCTAssertNil(EmptyAutofillOriginPolicy.requestedOrigin(
                .init(identifier: identifier, kind: .url)
            ), identifier)
        }
        XCTAssertNil(EmptyAutofillOriginPolicy.requestedOrigin(
            .init(identifier: "example.com", kind: .domain)
        ))
        XCTAssertNil(EmptyAutofillOriginPolicy.requestedOrigin(
            .init(identifier: "com.example.app", kind: .app)
        ))
    }

    func testSavedOriginMustMatchSchemeHostAndPort() {
        let credential = VaultCredential(
            title: "Example", serviceIdentifier: "https://example.com:8443/login",
            username: "alice", password: "demo-only"
        )
        XCTAssertTrue(EmptyAutofillOriginPolicy.matches(
            credential, service: .init(identifier: "https://example.com:8443/other", kind: .url)
        ))
        for identifier in ["https://example.com", "http://example.com:8443", "https://example.com:9443"] {
            XCTAssertFalse(EmptyAutofillOriginPolicy.matches(
                credential, service: .init(identifier: identifier, kind: .url)
            ), identifier)
        }
        let requested = EmptyAutofillOriginPolicy.Service(identifier: "https://example.com:8443/path", kind: .url)
        XCTAssertEqual(EmptyAutofillOriginPolicy.selectedCredential(
            id: credential.id, in: [credential], service: requested
        ), credential)
        XCTAssertNil(EmptyAutofillOriginPolicy.selectedCredential(
            id: UUID(), in: [credential], service: requested
        ))
        XCTAssertNil(EmptyAutofillOriginPolicy.selectedCredential(
            id: credential.id, in: [credential],
            service: .init(identifier: "https://example.com:9443", kind: .url)
        ))
    }
}
