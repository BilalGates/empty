import Foundation
import XCTest
@testable import SpaceShared

final class SpaceAutofillOriginPolicyTests: XCTestCase {
    func testAcceptsOnlyCanonicalURLRequestOrigins() {
        let valid: [String: String] = [
            "https://example.com": "https://example.com",
            "https://example.com/login": "https://example.com",
            "https://example.com:8443/path?q=1": "https://example.com:8443",
            "http://localhost:8080/login": "http://localhost:8080"
        ]
        for (identifier, origin) in valid {
            XCTAssertEqual(SpaceAutofillOriginPolicy.requestedOrigin(
                .init(identifier: identifier, kind: .url)
            ), origin, identifier)
        }
        for identifier in [
            "example.com", "https://Example.com", "https://example.com:443/login",
            "http://example.com", "https://user@example.com",
            "https://xn--a.example", "https://example.com:0443", "https://example.com\\@evil.com"
        ] {
            XCTAssertNil(SpaceAutofillOriginPolicy.requestedOrigin(
                .init(identifier: identifier, kind: .url)
            ), identifier)
        }
        XCTAssertNil(SpaceAutofillOriginPolicy.requestedOrigin(
            .init(identifier: "example.com", kind: .domain)
        ))
        XCTAssertNil(SpaceAutofillOriginPolicy.requestedOrigin(
            .init(identifier: "com.example.app", kind: .app)
        ))
    }

    func testSavedOriginMustMatchSchemeHostAndPort() {
        let credential = VaultCredential(
            title: "Example", serviceIdentifier: "https://example.com:8443/login",
            username: "alice", password: "demo-only"
        )
        XCTAssertTrue(SpaceAutofillOriginPolicy.matches(
            credential, service: .init(identifier: "https://example.com:8443/other", kind: .url)
        ))
        for identifier in ["https://example.com", "http://example.com:8443", "https://example.com:9443"] {
            XCTAssertFalse(SpaceAutofillOriginPolicy.matches(
                credential, service: .init(identifier: identifier, kind: .url)
            ), identifier)
        }
        let requested = SpaceAutofillOriginPolicy.Service(identifier: "https://example.com:8443/path", kind: .url)
        XCTAssertEqual(SpaceAutofillOriginPolicy.selectedCredential(
            id: credential.id, in: [credential], service: requested
        ), credential)
        XCTAssertNil(SpaceAutofillOriginPolicy.selectedCredential(
            id: UUID(), in: [credential], service: requested
        ))
        XCTAssertNil(SpaceAutofillOriginPolicy.selectedCredential(
            id: credential.id, in: [credential],
            service: .init(identifier: "https://example.com:9443", kind: .url)
        ))
    }
}
