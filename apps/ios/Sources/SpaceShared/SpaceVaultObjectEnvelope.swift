import Foundation

/// Isolated V1 envelope reader. The caller must supply authenticated routing context.
/// Returned bytes are authenticated deterministic CBOR; a type-specific decoder must validate them
/// before any credential is used. This reader is not wired into local cache or sync.
public enum SpaceVaultObjectEnvelope {
    public enum Error: Swift.Error, Equatable {
        case invalidEnvelope
    }

    public static let maximumPlaintextBytes = 1_024 * 1_024 - 16
    private static let maximumCiphertextBytes = 1_024 * 1_024
    private static let maximumArtifactBytes = 16 * 1_024 * 1_024

    public static func open(
        artifact: Data,
        vrk: Data,
        expected: SpaceVaultObjectContext
    ) throws -> Data {
        var vaultWrapKey: Data?
        var dek: Data?
        var plaintext: Data?
        defer {
            wipe(&vaultWrapKey)
            wipe(&dek)
            wipe(&plaintext)
        }
        do {
            let aad = try expected.encodedAAD()
            let record = try parse(artifact)
            guard sameBytes(record.aad, aad) else { throw Error.invalidEnvelope }

            let suite = try SpaceVaultPrimitiveSuite()
            vaultWrapKey = try suite.deriveVaultWrapKey(vrk: vrk, vaultID: expected.vaultID)
            dek = try suite.open(
                ciphertext: record.wrappedDek.ciphertext,
                key: vaultWrapKey!,
                nonce: record.wrappedDek.nonce,
                authenticatedData: aad + Data([0]) + Data("dek".utf8)
            )
            guard dek?.count == SpaceVaultPrimitiveSuite.keySize else { throw Error.invalidEnvelope }
            plaintext = try suite.open(
                ciphertext: record.payload.ciphertext,
                key: dek!,
                nonce: record.payload.nonce,
                authenticatedData: aad + Data([0]) + Data("payload".utf8)
            )
            guard let size = plaintext?.count, size <= maximumPlaintextBytes else { throw Error.invalidEnvelope }
            try SpaceDeterministicCBOR.validate(plaintext!, maximumBytes: maximumPlaintextBytes)
            let result = plaintext!
            plaintext = nil // transfer ownership to the caller after validation
            return result
        } catch {
            throw Error.invalidEnvelope
        }
    }

    private static func wipe(_ value: inout Data?) {
        guard let count = value?.count else { return }
        value?.resetBytes(in: 0..<count)
        value = nil
    }

    private static func sameBytes(_ left: Data, _ right: Data) -> Bool {
        var difference = left.count ^ right.count
        for index in 0..<max(left.count, right.count) {
            let l = index < left.count ? left[left.index(left.startIndex, offsetBy: index)] : 0
            let r = index < right.count ? right[right.index(right.startIndex, offsetBy: index)] : 0
            difference |= Int(l ^ r)
        }
        return difference == 0
    }

    private struct SealedBytes {
        let nonce: Data
        let ciphertext: Data
    }

    private struct Record {
        let aad: Data
        let wrappedDek: SealedBytes
        let payload: SealedBytes
    }

    private static func parse(_ artifact: Data) throws -> Record {
        guard artifact.count >= 12, artifact.count <= maximumArtifactBytes else { throw Error.invalidEnvelope }
        var reader = Reader(data: artifact)
        try reader.expect(0x53); try reader.expect(0x50); try reader.expect(0x43); try reader.expect(0x45)
        try reader.expect(0); try reader.expect(1); try reader.expect(1)
        let bodyLength = try reader.readUInt32()
        guard bodyLength == artifact.count - 11 else { throw Error.invalidEnvelope }

        try reader.expect(0xa3)
        try reader.expect(1)
        let aad = try reader.readByteString(maximum: 16 * 1_024)
        try reader.expect(2)
        let wrappedDek = try reader.readSealedBytes(maximumCiphertext: 48)
        guard wrappedDek.ciphertext.count == 48 else { throw Error.invalidEnvelope }
        try reader.expect(3)
        let payload = try reader.readSealedBytes(maximumCiphertext: maximumCiphertextBytes)
        guard payload.ciphertext.count >= SpaceVaultPrimitiveSuite.tagSize,
              reader.isAtEnd else { throw Error.invalidEnvelope }
        return Record(aad: aad, wrappedDek: wrappedDek, payload: payload)
    }

    private struct Reader {
        let data: Data
        private(set) var offset = 0

        var isAtEnd: Bool { offset == data.count }

        mutating func expect(_ expected: UInt8) throws {
            guard try readByte() == expected else { throw Error.invalidEnvelope }
        }

        mutating func readByte() throws -> UInt8 {
            guard offset < data.count else { throw Error.invalidEnvelope }
            let value = data[data.index(data.startIndex, offsetBy: offset)]
            offset += 1
            return value
        }

        mutating func readUInt32() throws -> Int {
            var value = 0
            for _ in 0..<4 { value = value * 256 + Int(try readByte()) }
            return value
        }

        mutating func readByteString(maximum: Int) throws -> Data {
            let initial = try readByte()
            guard initial >> 5 == 2 else { throw Error.invalidEnvelope }
            let additional = initial & 31
            let length: Int
            if additional < 24 {
                length = Int(additional)
            } else if additional == 24 {
                length = Int(try readByte())
                guard length >= 24 else { throw Error.invalidEnvelope }
            } else if additional == 25 {
                length = Int(try readByte()) * 256 + Int(try readByte())
                guard length >= 256 else { throw Error.invalidEnvelope }
            } else if additional == 26 {
                length = try readUInt32()
                guard length >= 65_536 else { throw Error.invalidEnvelope }
            } else {
                throw Error.invalidEnvelope
            }
            guard length <= maximum, length <= data.count - offset else { throw Error.invalidEnvelope }
            let start = data.index(data.startIndex, offsetBy: offset)
            offset += length
            let end = data.index(data.startIndex, offsetBy: offset)
            return data.subdata(in: start..<end)
        }

        mutating func readSealedBytes(maximumCiphertext: Int) throws -> SealedBytes {
            try expect(0xa2)
            try expect(1)
            let nonce = try readByteString(maximum: SpaceVaultPrimitiveSuite.nonceSize)
            guard nonce.count == SpaceVaultPrimitiveSuite.nonceSize else { throw Error.invalidEnvelope }
            try expect(2)
            let ciphertext = try readByteString(maximum: maximumCiphertext)
            return SealedBytes(nonce: nonce, ciphertext: ciphertext)
        }
    }
}
