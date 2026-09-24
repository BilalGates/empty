import Foundation

/// Typed V1 password payload. Only call after object AAD and both AEAD tags were checked.
public struct SpacePasswordPayload: Equatable, Sendable {
    public let title: String
    public let origins: [String]
    public let username: String
    public let password: String
    public let groupID: Data?
    public let notes: String?
    public let favorite: Bool
    public let createdAtMs: Int
    public let updatedAtMs: Int

    public enum Error: Swift.Error, Equatable { case invalidPayload }

    public static func decode(_ bytes: Data) throws -> Self {
        do {
            guard bytes.count <= SpaceVaultObjectEnvelope.maximumPlaintextBytes else { throw Error.invalidPayload }
            try SpaceDeterministicCBOR.validate(bytes, maximumBytes: SpaceVaultObjectEnvelope.maximumPlaintextBytes)
            var reader = Reader(bytes: bytes)
            let count = try reader.header(major: 5)
            guard (7...9).contains(count) else { throw Error.invalidPayload }
            var fields = [Int: Value]()
            for _ in 0..<count {
                let key = try reader.header(major: 0)
                guard (1...9).contains(key), fields[key] == nil else { throw Error.invalidPayload }
                switch key {
                case 1: fields[key] = .text(try reader.text(maximum: 256, allowEmpty: false))
                case 2:
                    let originCount = try reader.header(major: 4)
                    guard (1...16).contains(originCount) else { throw Error.invalidPayload }
                    var origins = [String]()
                    for _ in 0..<originCount { origins.append(try reader.text(maximum: 2_048, allowEmpty: false)) }
                    guard Set(origins).count == origins.count,
                          origins.allSatisfy(SpacePasswordOrigin.isCanonical) else { throw Error.invalidPayload }
                    fields[key] = .origins(origins)
                case 3: fields[key] = .text(try reader.text(maximum: 1_024, allowEmpty: true))
                case 4: fields[key] = .text(try reader.text(maximum: 65_536, allowEmpty: false))
                case 5:
                    let group = try reader.byteString()
                    guard group.count == 16 else { throw Error.invalidPayload }
                    fields[key] = .bytes(group)
                case 6: fields[key] = .text(try reader.text(maximum: 65_536, allowEmpty: true))
                case 7: fields[key] = .bool(try reader.boolean())
                case 8, 9:
                    let time = try reader.header(major: 0)
                    guard time > 0 else { throw Error.invalidPayload }
                    fields[key] = .integer(time)
                default: throw Error.invalidPayload
                }
            }
            guard reader.isAtEnd,
                  case let .text(title)? = fields[1],
                  case let .origins(origins)? = fields[2],
                  case let .text(username)? = fields[3],
                  case let .text(password)? = fields[4],
                  case let .bool(favorite)? = fields[7],
                  case let .integer(createdAtMs)? = fields[8],
                  case let .integer(updatedAtMs)? = fields[9],
                  updatedAtMs >= createdAtMs else { throw Error.invalidPayload }
            var groupID: Data?
            if let value = fields[5] {
                guard case let .bytes(group) = value else { throw Error.invalidPayload }
                groupID = group
            }
            var notes: String?
            if let value = fields[6] {
                guard case let .text(note) = value else { throw Error.invalidPayload }
                notes = note
            }
            return Self(title: title, origins: origins, username: username, password: password,
                        groupID: groupID, notes: notes, favorite: favorite,
                        createdAtMs: createdAtMs, updatedAtMs: updatedAtMs)
        } catch { throw Error.invalidPayload }
    }

    private enum Value {
        case text(String), origins([String]), bytes(Data), bool(Bool), integer(Int)
    }

    private struct Reader {
        let bytes: Data
        private(set) var offset = 0
        var isAtEnd: Bool { offset == bytes.count }

        mutating func byte() throws -> UInt8 {
            guard offset < bytes.count else { throw Error.invalidPayload }
            defer { offset += 1 }
            return bytes[bytes.index(bytes.startIndex, offsetBy: offset)]
        }

        mutating func header(major: UInt8) throws -> Int {
            let initial = try byte()
            guard initial >> 5 == major else { throw Error.invalidPayload }
            let additional = initial & 31
            if additional < 24 { return Int(additional) }
            let width: Int
            switch additional {
            case 24: width = 1
            case 25: width = 2
            case 26: width = 4
            case 27: width = 8
            default: throw Error.invalidPayload
            }
            var value: UInt64 = 0
            for _ in 0..<width { value = value * 256 + UInt64(try byte()) }
            guard value <= 9_007_199_254_740_991 else { throw Error.invalidPayload }
            return Int(value)
        }

        mutating func text(maximum: Int, allowEmpty: Bool) throws -> String {
            let length = try header(major: 3)
            guard (allowEmpty || length > 0), length <= maximum,
                  length <= bytes.count - offset else { throw Error.invalidPayload }
            let start = bytes.index(bytes.startIndex, offsetBy: offset)
            offset += length
            let end = bytes.index(bytes.startIndex, offsetBy: offset)
            guard let text = String(data: bytes.subdata(in: start..<end), encoding: .utf8) else {
                throw Error.invalidPayload
            }
            return text
        }

        mutating func byteString() throws -> Data {
            let length = try header(major: 2)
            guard length <= 16, length <= bytes.count - offset else { throw Error.invalidPayload }
            let start = bytes.index(bytes.startIndex, offsetBy: offset)
            offset += length
            let end = bytes.index(bytes.startIndex, offsetBy: offset)
            return bytes.subdata(in: start..<end)
        }

        mutating func boolean() throws -> Bool {
            switch try byte() {
            case 0xf4: return false
            case 0xf5: return true
            default: throw Error.invalidPayload
            }
        }
    }
}
