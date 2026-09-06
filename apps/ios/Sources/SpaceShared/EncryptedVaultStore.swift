import CryptoKit
import Foundation

public actor EncryptedVaultStore {
    private let fileURL: URL
    private let vaultID: UUID
    private let keyStore: any UnlockKeyProviding

    public init(fileURL: URL, vaultID: UUID, keyStore: any UnlockKeyProviding) {
        self.fileURL = fileURL
        self.vaultID = vaultID
        self.keyStore = keyStore
    }

    public func load(interaction: UnlockInteraction) throws -> VaultSnapshot {
        let key = try keyStore.load(interaction: interaction)
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return VaultSnapshot(credentials: [])
        }
        let attributes = try fileURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard attributes.isRegularFile == true,
              let fileSize = attributes.fileSize,
              fileSize <= LocalCacheEnvelope.maximumEnvelopeSize else {
            throw LocalCacheEnvelope.EnvelopeError.oversized
        }
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        let envelope = try handle.read(
            upToCount: LocalCacheEnvelope.maximumEnvelopeSize + 1
        ) ?? Data()
        // Keep this post-read guard: the file may have changed after the metadata preflight.
        guard envelope.count <= LocalCacheEnvelope.maximumEnvelopeSize else {
            throw LocalCacheEnvelope.EnvelopeError.oversized
        }
        let plaintext = try LocalCacheEnvelope.open(
            envelope,
            expectedVaultID: vaultID,
            key: key
        )
        do {
            return try JSONDecoder().decode(VaultSnapshot.self, from: plaintext)
        } catch {
            throw LocalCacheEnvelope.EnvelopeError.invalidEnvelope
        }
    }

    public func save(_ snapshot: VaultSnapshot, interaction: UnlockInteraction) throws {
        try keyStore.createIfNeeded()
        let key = try keyStore.load(interaction: interaction)
        let plaintext = try JSONEncoder().encode(snapshot)
        let envelope = try LocalCacheEnvelope.seal(plaintext, vaultID: vaultID, key: key)
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try envelope.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }
}
