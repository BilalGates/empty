import CryptoKit
import Foundation
import XCTest
@testable import SpaceShared

final class LocalCacheEnvelopeTests: XCTestCase {
    private let vaultID = UUID(uuidString: "B531522C-E28A-4B33-9D5B-4B83F05DD047")!
    private let key = SymmetricKey(data: Data(repeating: 0x2a, count: 32))

    func testRoundTrip() throws {
        let plaintext = Data("classified".utf8)
        let envelope = try LocalCacheEnvelope.seal(plaintext, vaultID: vaultID, key: key)
        XCTAssertEqual(
            try LocalCacheEnvelope.open(envelope, expectedVaultID: vaultID, key: key),
            plaintext
        )
        XCTAssertNotEqual(envelope.suffix(plaintext.count), plaintext)
    }

    func testFreshNonceProducesDifferentEnvelope() throws {
        let plaintext = Data("same".utf8)
        XCTAssertNotEqual(
            try LocalCacheEnvelope.seal(plaintext, vaultID: vaultID, key: key),
            try LocalCacheEnvelope.seal(plaintext, vaultID: vaultID, key: key)
        )
    }

    func testMutationFailsClosed() throws {
        var envelope = try LocalCacheEnvelope.seal(Data("secret".utf8), vaultID: vaultID, key: key)
        envelope[envelope.index(before: envelope.endIndex)] ^= 0x01
        XCTAssertThrowsError(
            try LocalCacheEnvelope.open(envelope, expectedVaultID: vaultID, key: key)
        ) { error in
            XCTAssertEqual(error as? LocalCacheEnvelope.EnvelopeError, .invalidEnvelope)
        }
    }

    func testCrossVaultSubstitutionFails() throws {
        let envelope = try LocalCacheEnvelope.seal(Data(), vaultID: vaultID, key: key)
        XCTAssertThrowsError(
            try LocalCacheEnvelope.open(envelope, expectedVaultID: UUID(), key: key)
        )
    }

    func testWrongKeyHasSameExternalErrorAsTamper() throws {
        let envelope = try LocalCacheEnvelope.seal(Data("secret".utf8), vaultID: vaultID, key: key)
        let wrongKey = SymmetricKey(data: Data(repeating: 0x7b, count: 32))
        XCTAssertThrowsError(
            try LocalCacheEnvelope.open(envelope, expectedVaultID: vaultID, key: wrongKey)
        ) { error in
            XCTAssertEqual(error as? LocalCacheEnvelope.EnvelopeError, .invalidEnvelope)
        }
    }

    func testRejectsOversizedInputBeforeCrypto() {
        let bytes = Data(count: LocalCacheEnvelope.maximumPlaintextSize + 1)
        XCTAssertThrowsError(try LocalCacheEnvelope.seal(bytes, vaultID: vaultID, key: key)) {
            XCTAssertEqual($0 as? LocalCacheEnvelope.EnvelopeError, .oversized)
        }
    }

    func testRejectsTruncatedEnvelopeAtExplicitMinimum() {
        let bytes = Data(count: LocalCacheEnvelope.minimumEnvelopeSize - 1)
        XCTAssertThrowsError(
            try LocalCacheEnvelope.open(bytes, expectedVaultID: vaultID, key: key)
        ) { error in
            XCTAssertEqual(error as? LocalCacheEnvelope.EnvelopeError, .invalidEnvelope)
        }
    }

    func testPlaintextAndEnvelopeLimitsAreConsistent() {
        XCTAssertEqual(
            LocalCacheEnvelope.maximumPlaintextSize + LocalCacheEnvelope.minimumEnvelopeSize,
            LocalCacheEnvelope.maximumEnvelopeSize
        )
    }
}
