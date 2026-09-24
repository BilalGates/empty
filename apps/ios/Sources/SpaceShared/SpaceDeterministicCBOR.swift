import Foundation

/// Validates the bounded deterministic-CBOR subset shared with the TypeScript protocol.
/// Validation does not assign a credential schema or expose decoded secret fields.
public enum SpaceDeterministicCBOR {
    public enum Error: Swift.Error, Equatable { case invalidCBOR }

    public static func validate(_ bytes: Data, maximumBytes: Int = 16 * 1_024 * 1_024) throws {
        guard maximumBytes > 0, maximumBytes <= 16 * 1_024 * 1_024,
              bytes.count <= maximumBytes else { throw Error.invalidCBOR }
        var reader = Reader(bytes: bytes)
        try reader.parse(depth: 0)
        guard reader.isAtEnd else { throw Error.invalidCBOR }
    }

    private struct Reader {
        let bytes: Data
        private(set) var offset = 0
        private let maximumSafeInteger: UInt64 = 9_007_199_254_740_991

        var isAtEnd: Bool { offset == bytes.count }

        mutating func readByte() throws -> UInt8 {
            guard offset < bytes.count else { throw Error.invalidCBOR }
            let value = bytes[bytes.index(bytes.startIndex, offsetBy: offset)]
            offset += 1
            return value
        }

        mutating func argument(_ additional: UInt8) throws -> Int {
            if additional < 24 { return Int(additional) }
            let width: Int
            let minimum: UInt64
            switch additional {
            case 24: width = 1; minimum = 24
            case 25: width = 2; minimum = 256
            case 26: width = 4; minimum = 65_536
            case 27: width = 8; minimum = 4_294_967_296
            default: throw Error.invalidCBOR
            }
            var value: UInt64 = 0
            for _ in 0..<width { value = value * 256 + UInt64(try readByte()) }
            guard value >= minimum, value <= maximumSafeInteger else { throw Error.invalidCBOR }
            return Int(value)
        }

        mutating func parse(depth: Int) throws {
            guard depth <= 16 else { throw Error.invalidCBOR }
            let initial = try readByte()
            let major = initial >> 5
            let additional = initial & 31
            if major == 7 {
                guard initial == 0xf4 || initial == 0xf5 || initial == 0xf6 else { throw Error.invalidCBOR }
                return
            }
            guard major <= 5 else { throw Error.invalidCBOR }
            let length = try argument(additional)
            switch major {
            case 0: return
            case 1:
                guard UInt64(length) < maximumSafeInteger else { throw Error.invalidCBOR }
            case 2, 3:
                guard length <= 1_024 * 1_024,
                      length <= bytes.count - offset else { throw Error.invalidCBOR }
                if major == 3 {
                    let start = bytes.index(bytes.startIndex, offsetBy: offset)
                    let end = bytes.index(start, offsetBy: length)
                    guard String(data: bytes.subdata(in: start..<end), encoding: .utf8) != nil else {
                        throw Error.invalidCBOR
                    }
                }
                offset += length
            case 4:
                guard length <= bytes.count - offset else { throw Error.invalidCBOR }
                for _ in 0..<length { try parse(depth: depth + 1) }
            case 5:
                guard length <= 64, length * 2 <= bytes.count - offset else { throw Error.invalidCBOR }
                if length > 0 && depth == 16 { throw Error.invalidCBOR }
                var previousKey: Data?
                for _ in 0..<length {
                    let startOffset = offset
                    let keyInitial = try readByte()
                    guard keyInitial >> 5 == 0 else { throw Error.invalidCBOR }
                    _ = try argument(keyInitial & 31)
                    let start = bytes.index(bytes.startIndex, offsetBy: startOffset)
                    let end = bytes.index(bytes.startIndex, offsetBy: offset)
                    let keyBytes = bytes.subdata(in: start..<end)
                    if let previousKey {
                        guard previousKey.count < keyBytes.count ||
                                (previousKey.count == keyBytes.count && previousKey.lexicographicallyPrecedes(keyBytes)) else {
                            throw Error.invalidCBOR
                        }
                    }
                    previousKey = keyBytes
                    try parse(depth: depth + 1)
                }
            default: throw Error.invalidCBOR
            }
        }
    }
}
