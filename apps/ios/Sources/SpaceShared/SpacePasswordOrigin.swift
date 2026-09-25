import Foundation

/// Exact V1 wire origin grammar. This does not turn a URL or a service identifier into an origin.
public enum SpacePasswordOrigin {
    public static func isCanonical(_ value: String) -> Bool {
        guard value.utf8.count <= 2_048,
              let expression = try? NSRegularExpression(
                pattern: #"\A(https?):\/\/([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?\z"#
              ) else { return false }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        guard let match = expression.firstMatch(in: value, range: range), match.range == range,
              let schemeRange = Range(match.range(at: 1), in: value),
              let hostRange = Range(match.range(at: 2), in: value) else { return false }
        let scheme = String(value[schemeRange])
        let host = String(value[hostRange])
        guard host.utf8.count <= 253 else { return false }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        let numericHost = host.allSatisfy { $0 == "." || $0.isASCIIDigit }
        if numericHost {
            guard labels.count == 4, labels.allSatisfy({ label in
                guard !label.isEmpty, label.count <= 3,
                      label == "0" || label.first != "0",
                      let octet = UInt8(label) else { return false }
                return String(octet) == label
            }) else { return false }
        } else {
            guard host == "localhost" || (labels.count >= 2 && labels.last!.first?.isASCIILower == true) else {
                return false
            }
            guard labels.allSatisfy({ label in
                guard (1...63).contains(label.count), !label.hasPrefix("xn--"),
                      let first = label.first, let last = label.last,
                      first.isASCIIAlphaNumeric, last.isASCIIAlphaNumeric else { return false }
                return label.allSatisfy { $0.isASCIIAlphaNumeric || $0 == "-" }
            }) else { return false }
        }
        if scheme == "http" && host != "localhost" && host != "127.0.0.1" { return false }
        if match.range(at: 3).location != NSNotFound {
            guard let portRange = Range(match.range(at: 3), in: value),
                  let port = UInt16(value[portRange]), port > 0,
                  !(scheme == "https" && port == 443),
                  !(scheme == "http" && port == 80) else { return false }
        }
        return true
    }
}

private extension Character {
    var isASCIIDigit: Bool { unicodeScalars.count == 1 && unicodeScalars.first!.value >= 48 && unicodeScalars.first!.value <= 57 }
    var isASCIILower: Bool { unicodeScalars.count == 1 && unicodeScalars.first!.value >= 97 && unicodeScalars.first!.value <= 122 }
    var isASCIIAlphaNumeric: Bool { isASCIIDigit || isASCIILower }
}
