import Foundation

/// Isolated V1 envelope reader/writer. The caller must supply authenticated routing context.
/// Returned bytes are authenticated deterministic CBOR; a type-specific decoder must validate them
/// before any credential is used. This reader is not wired into local cache or sync.
public enum SpaceVaultObjectEnvelope {
    public enum Error: Swift.Error, Equatable {
        case invalidEnvelope
    }

    public static let maximumPlaintextBytes = 1_024 * 1_024 - 16
    private static let maximumCiphertextBytes = 1_024 * 1_024
    private static let maximumArtifactBytes = 16 * 1_024 * 1_024

    /// Produces an isolated password object with a fresh DEK and two fresh nonces.
    /// The caller supplies deterministic, type-validated password CBOR bytes.
    public static func sealPassword(
        plaintextCBOR: Data,
        vrk: Data,
        context: SpaceVaultObjectContext
    ) throws -> Data {
        guard context.objectType == .password else { throw Error.invalidEnvelope }
        do {
            _ = try SpacePasswordPayload.decode(plaintextCBOR)
            let suite = try SpaceVaultPrimitiveSuite()
            var dek: Data? = try suite.randomKey()
            defer { wipe(&dek) }
            return try sealUsingMaterial(
                plaintextCBOR: plaintextCBOR, vrk: vrk, context: context,
                dek: dek!, wrappedNonce: suite.randomNonce(), payloadNonce: suite.randomNonce()
            )
        } catch { throw Error.invalidEnvelope }
    }

    /// Internal deterministic seam for the shared independent vector; app targets cannot call it.
    static func sealUsingMaterial(
        plaintextCBOR: Data,
        vrk: Data,
        context: SpaceVaultObjectContext,
        dek: Data,
        wrappedNonce: Data,
        payloadNonce: Data
    ) throws -> Data {
        var vaultWrapKey: Data?
        defer { wipe(&vaultWrapKey) }
        do {
            guard plaintextCBOR.count <= maximumPlaintextBytes,
                  dek.count == SpaceVaultPrimitiveSuite.keySize,
                  wrappedNonce.count == SpaceVaultPrimitiveSuite.nonceSize,
                  payloadNonce.count == SpaceVaultPrimitiveSuite.nonceSize else { throw Error.invalidEnvelope }
            try SpaceDeterministicCBOR.validate(plaintextCBOR, maximumBytes: maximumPlaintextBytes)
            let aad = try context.encodedAAD()
            guard aad.count <= 16 * 1_024 else { throw Error.invalidEnvelope }
            let suite = try SpaceVaultPrimitiveSuite()
            vaultWrapKey = try suite.deriveVaultWrapKey(vrk: vrk, vaultID: context.vaultID)
            let wrapped = try suite.seal(
                plaintext: dek, key: vaultWrapKey!, nonce: wrappedNonce,
                authenticatedData: aad + Data([0]) + Data("dek".utf8)
            )
            let ciphertext = try suite.seal(
                plaintext: plaintextCBOR, key: dek, nonce: payloadNonce,
                authenticatedData: aad + Data([0]) + Data("payload".utf8)
            )
            guard wrapped.count == 48, ciphertext.count <= maximumCiphertextBytes else {
                throw Error.invalidEnvelope
            }
            var body = Data([0xa3, 0x01])
            try appendByteString(aad, to: &body)
            body.append(contentsOf: [0x02, 0xa2, 0x01])
            try appendByteString(wrappedNonce, to: &body)
            body.append(0x02)
            try appendByteString(wrapped, to: &body)
            body.append(contentsOf: [0x03, 0xa2, 0x01])
            try appendByteString(payloadNonce, to: &body)
            body.append(0x02)
            try appendByteString(ciphertext, to: &body)
            guard body.count <= maximumArtifactBytes - 11, body.count <= Int(UInt32.max) else {
                throw Error.invalidEnvelope
            }
            var artifact = Data([0x53, 0x50, 0x43, 0x45, 0x00, 0x01, 0x01])
            let length = UInt32(body.count).bigEndian
            artifact.append(contentsOf: withUnsafeBytes(of: length, Array.init))
            artifact.append(body)
            return artifact
        } catch { throw Error.invalidEnvelope }
    }

    private static func appendByteString(_ value: Data, to output: inout Data) throws {
        let count = value.count
        guard count <= 1_024 * 1_024 else { throw Error.invalidEnvelope }
        if count < 24 {
            output.append(0x40 | UInt8(count))
        } else if count <= Int(UInt8.max) {
            output.append(contentsOf: [0x58, UInt8(count)])
        } else if count <= Int(UInt16.max) {
            output.append(0x59)
            output.append(contentsOf: withUnsafeBytes(of: UInt16(count).bigEndian, Array.init))
        } else {
            output.append(0x5a)
            output.append(contentsOf: withUnsafeBytes(of: UInt32(count).bigEndian, Array.init))
        }
        output.append(value)
    }

    public static func openPassword(
        artifact: Data,
        vrk: Data,
        expected: SpaceVaultObjectContext
    ) throws -> SpacePasswordPayload {
        guard expected.objectType == .password else { throw Error.invalidEnvelope }
        var plaintext: Data?
        defer { wipe(&plaintext) }
        do {
            plaintext = try open(artifact: artifact, vrk: vrk, expected: expected)
            return try SpacePasswordPayload.decode(plaintext!)
        } catch { throw Error.invalidEnvelope }
    }

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
