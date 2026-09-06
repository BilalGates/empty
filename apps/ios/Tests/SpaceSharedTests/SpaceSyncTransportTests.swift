import Foundation
import XCTest
@testable import SpaceShared

final class SpaceSyncTransportTests: XCTestCase {
    private let token = "space_dt_" + String(repeating: "0", count: 32)

    func testRequiresHTTPSForRemoteServers() {
        XCTAssertThrowsError(
            try SpaceDeviceSession(
                baseURL: URL(string: "http://sync.example.com")!,
                deviceToken: token
            )
        ) { error in
            XCTAssertEqual(error as? SpaceSyncError, .insecureEndpoint)
        }
    }

    func testRejectsCredentialsEmbeddedInEndpoint() {
        XCTAssertThrowsError(
            try SpaceDeviceSession(
                baseURL: URL(string: "https://user:password@sync.example.com")!,
                deviceToken: token
            )
        )
    }

    func testRejectsMalformedDeviceToken() {
        XCTAssertThrowsError(
            try SpaceDeviceSession(
                baseURL: URL(string: "https://sync.example.com")!,
                deviceToken: "secret"
            )
        ) { error in
            XCTAssertEqual(error as? SpaceSyncError, .invalidDeviceToken)
        }
    }

    func testMutationRequiresCompleteEnvelopeOrTombstone() throws {
        XCTAssertNoThrow(try mutation(ciphertext: nil, nonce: nil, wrappedKey: nil, aad: nil))
        XCTAssertThrowsError(
            try mutation(ciphertext: "ciphertext", nonce: nil, wrappedKey: "key", aad: "aad")
        ) { error in
            XCTAssertEqual(error as? SpaceSyncError, .invalidEnvelope)
        }
    }

    func testMutationWireKeysMatchAPIContract() throws {
        let value = try mutation(ciphertext: "ciphertext", nonce: "nonce", wrappedKey: "key", aad: "aad")
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            Set(["mutationId", "itemId", "baseItemVersion", "ciphertext", "nonce", "wrappedKey", "aad"])
        )
    }

    func testPersistedSessionIsRevalidated() throws {
        let valid = try SpaceDeviceSession(
            baseURL: URL(string: "https://sync.example.com")!,
            deviceToken: token
        )
        let data = try JSONEncoder().encode(valid)
        let decoded = try JSONDecoder().decode(SpaceDeviceSession.self, from: data)
        XCTAssertEqual(
            try SpaceDeviceSession(baseURL: decoded.baseURL, deviceToken: decoded.deviceToken),
            valid
        )
    }

    private func mutation(
        ciphertext: String?,
        nonce: String?,
        wrappedKey: String?,
        aad: String?
    ) throws -> OpaqueSyncMutation {
        try OpaqueSyncMutation(
            mutationId: UUID(),
            itemId: UUID(),
            baseItemVersion: 0,
            ciphertext: ciphertext,
            nonce: nonce,
            wrappedKey: wrappedKey,
            aad: aad
        )
    }
}
