import Foundation
import XCTest
@testable import SpaceShared

final class SpaceVaultPrimitiveSuiteTests: XCTestCase {
    func testArgon2idMatchesSharedVector() throws {
        let vector: ArgonVector = try loadVector("argon2id-v1")
        XCTAssertEqual(vector.suite, SpaceVaultPrimitiveSuite.suiteIdentifier)
        XCTAssertEqual(vector.parameters.memoryKiB, Int(SpaceVaultPrimitiveSuite.argonMemoryKiB))
        XCTAssertEqual(vector.parameters.iterations, Int(SpaceVaultPrimitiveSuite.argonIterations))
        XCTAssertEqual(vector.parameters.parallelism, Int(SpaceVaultPrimitiveSuite.argonParallelism))
        XCTAssertEqual(vector.parameters.outputBytes, SpaceVaultPrimitiveSuite.keySize)

        let suite = try SpaceVaultPrimitiveSuite()
        let passwordData = try Data(hex: vector.inputUtf8Hex)
        let password = try XCTUnwrap(String(data: passwordData, encoding: .utf8))
        let output = try suite.derivePasswordKey(
            password: password,
            salt: Data(hex: vector.saltHex)
        )
        XCTAssertEqual(output.hex, vector.outputHex)
    }

    func testPasswordUsesNFCWithoutTrimOrCaseFold() throws {
        let suite = try SpaceVaultPrimitiveSuite()
        let salt = Data((0..<16).map(UInt8.init))
        let composed = try suite.derivePasswordKey(password: "Café", salt: salt)
        let decomposed = try suite.derivePasswordKey(password: "Cafe\u{301}", salt: salt)
        let changedCase = try suite.derivePasswordKey(password: "CAFÉ", salt: salt)
        let padded = try suite.derivePasswordKey(password: " Café ", salt: salt)
        XCTAssertEqual(composed, decomposed)
        XCTAssertNotEqual(composed, changedCase)
        XCTAssertNotEqual(composed, padded)
    }

    func testXChaChaMatchesIndependentVectorAndOpens() throws {
        let vector: XChaChaVector = try loadVector("xchacha20-poly1305-v1")
        let suite = try SpaceVaultPrimitiveSuite()
        let plaintext = try Data(hex: vector.plaintextHex)
        let key = try Data(hex: vector.keyHex)
        let nonce = try Data(hex: vector.nonceHex)
        let aad = try Data(hex: vector.aadHex)
        let ciphertext = try suite.seal(
            plaintext: plaintext,
            key: key,
            nonce: nonce,
            authenticatedData: aad
        )
        XCTAssertEqual(ciphertext.hex, vector.ciphertextHex)
        XCTAssertEqual(
            try suite.open(
                ciphertext: ciphertext,
                key: key,
                nonce: nonce,
                authenticatedData: aad
            ),
            plaintext
        )
    }

    func testXChaChaMutationsFailWithOneExternalError() throws {
        let vector: XChaChaVector = try loadVector("xchacha20-poly1305-v1")
        let suite = try SpaceVaultPrimitiveSuite()
        let key = try Data(hex: vector.keyHex)
        let nonce = try Data(hex: vector.nonceHex)
        let aad = try Data(hex: vector.aadHex)
        var ciphertext = try Data(hex: vector.ciphertextHex)
        ciphertext[ciphertext.startIndex] ^= 1

        XCTAssertThrowsError(
            try suite.open(
                ciphertext: ciphertext,
                key: key,
                nonce: nonce,
                authenticatedData: aad
            )
        ) { XCTAssertEqual($0 as? SpaceVaultPrimitiveSuite.Error, .invalidEnvelope) }

        XCTAssertThrowsError(
            try suite.open(
                ciphertext: try Data(hex: vector.ciphertextHex),
                key: key,
                nonce: nonce,
                authenticatedData: aad + Data([0])
            )
        ) { XCTAssertEqual($0 as? SpaceVaultPrimitiveSuite.Error, .invalidEnvelope) }
    }

    func testHKDFVaultWrapKeyMatchesIndependentVector() throws {
        let vector: HKDFVector = try loadVector("hkdf-vwk-v1")
        let suite = try SpaceVaultPrimitiveSuite()
        let output = try suite.deriveVaultWrapKey(
            vrk: Data(hex: vector.ikmHex),
            vaultID: Data(hex: vector.saltHex)
        )
        XCTAssertEqual(output.hex, vector.outputHex)
    }

    func testRejectsDowngradedOrMalformedKDFInputsBeforeAllocation() throws {
        let suite = try SpaceVaultPrimitiveSuite()
        XCTAssertThrowsError(try suite.derivePasswordKey(password: "", salt: Data(count: 16)))
        XCTAssertThrowsError(try suite.derivePasswordKey(password: "valid", salt: Data(count: 15)))
        XCTAssertThrowsError(
            try suite.derivePasswordKey(
                password: String(repeating: "a", count: 1_025),
                salt: Data(count: 16)
            )
        )
    }

    func testRejectsOversizedAADBeforeEncryption() throws {
        let suite = try SpaceVaultPrimitiveSuite()
        XCTAssertThrowsError(
            try suite.seal(
                plaintext: Data(),
                key: Data(count: SpaceVaultPrimitiveSuite.keySize),
                nonce: Data(count: SpaceVaultPrimitiveSuite.nonceSize),
                authenticatedData: Data(
                    count: SpaceVaultPrimitiveSuite.maximumAuthenticatedDataSize + 1
                )
            )
        ) { error in
            XCTAssertEqual(error as? SpaceVaultPrimitiveSuite.Error, .invalidParameters)
        }
    }

    func testRejectsMalformedEnvelopeAndKeySizes() throws {
        let suite = try SpaceVaultPrimitiveSuite()
        XCTAssertThrowsError(
            try suite.seal(
                plaintext: Data(),
                key: Data(count: SpaceVaultPrimitiveSuite.keySize - 1),
                nonce: Data(count: SpaceVaultPrimitiveSuite.nonceSize),
                authenticatedData: Data()
            )
        ) { XCTAssertEqual($0 as? SpaceVaultPrimitiveSuite.Error, .invalidParameters) }
        XCTAssertThrowsError(
            try suite.open(
                ciphertext: Data(count: SpaceVaultPrimitiveSuite.tagSize - 1),
                key: Data(count: SpaceVaultPrimitiveSuite.keySize),
                nonce: Data(count: SpaceVaultPrimitiveSuite.nonceSize),
                authenticatedData: Data()
            )
        ) { XCTAssertEqual($0 as? SpaceVaultPrimitiveSuite.Error, .invalidEnvelope) }
        XCTAssertThrowsError(
            try suite.deriveVaultWrapKey(
                vrk: Data(count: SpaceVaultPrimitiveSuite.keySize),
                vaultID: Data(count: 15)
            )
        ) { XCTAssertEqual($0 as? SpaceVaultPrimitiveSuite.Error, .invalidParameters) }
    }

    func testRandomNonceUsesNormativeLengthAndDoesNotRepeat() throws {
        let suite = try SpaceVaultPrimitiveSuite()
        let first = try suite.randomNonce()
        let second = try suite.randomNonce()
        XCTAssertEqual(first.count, SpaceVaultPrimitiveSuite.nonceSize)
        XCTAssertEqual(second.count, SpaceVaultPrimitiveSuite.nonceSize)
        XCTAssertNotEqual(first, second)
    }

    private func loadVector<T: Decodable>(_ name: String) throws -> T {
        let bundle = Bundle(for: Self.self)
        let url = try XCTUnwrap(bundle.url(forResource: name, withExtension: "json"))
        return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
    }
}

private struct ArgonVector: Decodable {
    let suite: String
    let inputUtf8Hex: String
    let saltHex: String
    let outputHex: String
    let parameters: Parameters

    struct Parameters: Decodable {
        let memoryKiB: Int
        let iterations: Int
        let parallelism: Int
        let outputBytes: Int
    }
}

private struct XChaChaVector: Decodable {
    let keyHex: String
    let nonceHex: String
    let aadHex: String
    let plaintextHex: String
    let ciphertextHex: String
}

private struct HKDFVector: Decodable {
    let ikmHex: String
    let saltHex: String
    let outputHex: String
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else { throw HexError.invalid }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { throw HexError.invalid }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

private enum HexError: Error { case invalid }
