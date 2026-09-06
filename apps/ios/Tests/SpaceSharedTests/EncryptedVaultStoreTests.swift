import CryptoKit
import Foundation
import XCTest
@testable import SpaceShared

final class EncryptedVaultStoreTests: XCTestCase {
    func testSaveAndLoadRoundTrip() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keyStore = InMemoryKeyStore()
        let store = EncryptedVaultStore(
            fileURL: directory.appendingPathComponent("vault.bin"),
            vaultID: UUID(uuidString: "876FFFA3-3147-4C77-8F82-E8F314654142")!,
            keyStore: keyStore
        )
        let snapshot = VaultSnapshot(credentials: [
            VaultCredential(
                title: "Example",
                serviceIdentifier: "example.com",
                username: "someone",
                password: "secret"
            )
        ])
        try await store.save(snapshot, interaction: .allowed(reason: "test"))
        let loaded = try await store.load(interaction: .forbidden)
        XCTAssertEqual(loaded, snapshot)
    }

    func testRejectsOversizedFileBeforeEnvelopeParsing() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fileURL = directory.appendingPathComponent("vault.bin")
        try Data(count: LocalCacheEnvelope.maximumEnvelopeSize + 1).write(to: fileURL)
        let store = EncryptedVaultStore(
            fileURL: fileURL,
            vaultID: UUID(),
            keyStore: InMemoryKeyStore()
        )
        do {
            _ = try await store.load(interaction: .forbidden)
            XCTFail("Expected an oversized error")
        } catch {
            XCTAssertEqual(error as? LocalCacheEnvelope.EnvelopeError, .oversized)
        }
    }
}

private final class InMemoryKeyStore: UnlockKeyProviding, @unchecked Sendable {
    private let key = SymmetricKey(data: Data(repeating: 0x3c, count: 32))
    func createIfNeeded() throws {}
    func load(interaction: UnlockInteraction) throws -> SymmetricKey { key }
    func delete() throws {}
}
