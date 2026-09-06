import XCTest
@testable import SpaceShared

final class VaultCredentialTests: XCTestCase {
    func testMatchesNormalizedExactHost() {
        let credential = VaultCredential(
            title: "Example",
            serviceIdentifier: "https://Example.com/login",
            username: "person@example.com",
            password: "test-value"
        )
        XCTAssertTrue(credential.matches(serviceIdentifiers: ["example.com"]))
        XCTAssertFalse(credential.matches(serviceIdentifiers: ["notexample.com"]))
        XCTAssertFalse(credential.matches(serviceIdentifiers: ["login.example.com"]))
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
