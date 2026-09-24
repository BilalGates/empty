import Foundation

/// Exact deterministic-CBOR AAD for a `space.vault/1` object.
/// This is not connected to the local preview cache or remote sync.
public enum SpaceVaultObjectAAD {
    public enum ObjectType: String, Sendable {
        case password, passkey, totp, tombstone
        case secureItem = "secure-item"
    }

    public enum Error: Swift.Error, Equatable {
        case invalidParameters
    }

    public static func encode(
        vaultID: Data,
        objectID: Data,
        objectType: ObjectType,
        objectVersion: Int,
        epoch: Int,
        keyID: Data,
        createdByDevice: Data
    ) throws -> Data {
        guard vaultID.count == 16, objectID.count == 16, keyID.count == 16,
              createdByDevice.count == 16, objectVersion > 0, epoch > 0,
              objectVersion <= 9_007_199_254_740_991, epoch <= 9_007_199_254_740_991 else {
            throw Error.invalidParameters
        }

        var output = Data([0xa9]) // nine canonical integer-keyed map entries
        appendUnsigned(1, to: &output); appendText("space.vault/1", to: &output)
        appendUnsigned(2, to: &output); appendText("vault-object", to: &output)
        appendUnsigned(3, to: &output); appendBytes(vaultID, to: &output)
        appendUnsigned(4, to: &output); appendBytes(objectID, to: &output)
        appendUnsigned(5, to: &output); appendText(objectType.rawValue, to: &output)
        appendUnsigned(6, to: &output); appendUnsigned(UInt64(objectVersion), to: &output)
        appendUnsigned(7, to: &output); appendUnsigned(UInt64(epoch), to: &output)
        appendUnsigned(8, to: &output); appendBytes(keyID, to: &output)
        appendUnsigned(9, to: &output); appendBytes(createdByDevice, to: &output)
        return output
    }

    private static func appendUnsigned(_ value: UInt64, to output: inout Data) {
        appendHeader(major: 0, length: value, to: &output)
    }

    private static func appendText(_ value: String, to output: inout Data) {
        let bytes = Data(value.utf8)
        appendHeader(major: 3, length: UInt64(bytes.count), to: &output)
        output.append(bytes)
    }

    private static func appendBytes(_ value: Data, to output: inout Data) {
        appendHeader(major: 2, length: UInt64(value.count), to: &output)
        output.append(value)
    }

    private static func appendHeader(major: UInt8, length: UInt64, to output: inout Data) {
        let prefix = major << 5
        if length < 24 {
            output.append(prefix | UInt8(length))
        } else if length <= UInt8.max {
            output.append(prefix | 24)
            output.append(UInt8(length))
        } else if length <= UInt16.max {
            output.append(prefix | 25)
            output.append(contentsOf: withUnsafeBytes(of: UInt16(length).bigEndian, Array.init))
        } else if length <= UInt32.max {
            output.append(prefix | 26)
            output.append(contentsOf: withUnsafeBytes(of: UInt32(length).bigEndian, Array.init))
        } else {
            output.append(prefix | 27)
            output.append(contentsOf: withUnsafeBytes(of: length.bigEndian, Array.init))
        }
    }
}

public struct SpaceVaultObjectContext: Sendable {
    public let vaultID: Data
    public let objectID: Data
    public let objectType: SpaceVaultObjectAAD.ObjectType
    public let objectVersion: Int
    public let epoch: Int
    public let keyID: Data
    public let createdByDevice: Data

    public init(
        vaultID: Data,
        objectID: Data,
        objectType: SpaceVaultObjectAAD.ObjectType,
        objectVersion: Int,
        epoch: Int,
        keyID: Data,
        createdByDevice: Data
    ) {
        self.vaultID = vaultID
        self.objectID = objectID
        self.objectType = objectType
        self.objectVersion = objectVersion
        self.epoch = epoch
        self.keyID = keyID
        self.createdByDevice = createdByDevice
    }

    public func encodedAAD() throws -> Data {
        try SpaceVaultObjectAAD.encode(
            vaultID: vaultID,
            objectID: objectID,
            objectType: objectType,
            objectVersion: objectVersion,
            epoch: epoch,
            keyID: keyID,
            createdByDevice: createdByDevice
        )
    }
}
