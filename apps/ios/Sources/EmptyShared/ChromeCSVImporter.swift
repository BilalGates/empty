import Foundation

public struct ChromeImportIssue: Equatable, Sendable {
    public let row: Int
    public let message: String
}

public struct ImportedPassword: Equatable, Sendable {
    public let title: String
    public let serviceIdentifier: String
    public let username: String
    public let password: String
}

public struct ChromeImportResult: Equatable, Sendable {
    public let accepted: [ImportedPassword]
    public let duplicates: Int
    public let issues: [ChromeImportIssue]
}

public enum ChromeCSVImportError: Error, Equatable {
    case oversized
    case unreadable
    case invalidEncoding
    case unsupportedHeader
    case malformedCSV
    case tooManyRows
}

public enum ChromeCSVImporter {
    public static let maximumFileSize = 5_000_000
    public static let maximumRows = 100_000

    public static func parse(fileURL: URL) throws -> ChromeImportResult {
#if canImport(Darwin)
        let accessGranted = fileURL.startAccessingSecurityScopedResource()
        defer { if accessGranted { fileURL.stopAccessingSecurityScopedResource() } }
#endif
        let values = try fileURL.resourceValues(
            forKeys: [.fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey]
        )
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw ChromeCSVImportError.unreadable
        }
        guard let fileSize = values.fileSize, fileSize <= maximumFileSize else {
            throw ChromeCSVImportError.oversized
        }
        let handle: FileHandle
        do { handle = try FileHandle(forReadingFrom: fileURL) }
        catch { throw ChromeCSVImportError.unreadable }
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maximumFileSize + 1) ?? Data()
        guard data.count <= maximumFileSize else { throw ChromeCSVImportError.oversized }
        return try parse(data: data)
    }

    public static func parse(data: Data) throws -> ChromeImportResult {
        guard data.count <= maximumFileSize else { throw ChromeCSVImportError.oversized }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ChromeCSVImportError.invalidEncoding
        }
        var rows = try rows(from: text)
        guard let rawHeader = rows.first else { throw ChromeCSVImportError.unsupportedHeader }
        rows.removeFirst()
        let header = rawHeader.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
                .trimmingCharacters(in: CharacterSet(charactersIn: "\u{feff}"))
        }
        func index(_ names: Set<String>) -> Int? { header.firstIndex(where: names.contains) }
        guard let websiteIndex = index(["url"]),
              let usernameIndex = index(["username"]),
              let passwordIndex = index(["password"]) else {
            throw ChromeCSVImportError.unsupportedHeader
        }
        let titleIndex = index(["name", "title"])
        var accepted: [ImportedPassword] = []
        var issues: [ChromeImportIssue] = []
        var duplicates = 0
        var seen = Set<String>()
        for (offset, columns) in rows.enumerated() {
            let rowNumber = offset + 2
            let website = value(at: websiteIndex, in: columns).trimmingCharacters(in: .whitespacesAndNewlines)
            let username = value(at: usernameIndex, in: columns)
            let password = value(at: passwordIndex, in: columns)
            guard !password.isEmpty,
                  let service = VaultCredential.canonicalServiceIdentifier(website),
                  let host = URLComponents(string: service)?.host else {
                issues.append(ChromeImportIssue(row: rowNumber, message: "Invalid website or empty password"))
                continue
            }
            let rawTitle = titleIndex.map { value(at: $0, in: columns) }
                ?? ""
            let title = rawTitle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? host
                : rawTitle.trimmingCharacters(in: .whitespacesAndNewlines)
            let key = "\(service)\u{0}\(username)\u{0}\(password)"
            guard seen.insert(key).inserted else { duplicates += 1; continue }
            accepted.append(ImportedPassword(
                title: title,
                serviceIdentifier: service,
                username: username,
                password: password
            ))
        }
        return ChromeImportResult(accepted: accepted, duplicates: duplicates, issues: issues)
    }

    private static func rows(from text: String) throws -> [[String]] {
        var result: [[String]] = []
        var row: [String] = []
        var field = ""
        var quoted = false
        var index = text.startIndex
        while index < text.endIndex {
            let character = text[index]
            let next = text.index(after: index)
            if quoted {
                if character == "\"" && next < text.endIndex && text[next] == "\"" {
                    field.append("\"")
                    index = text.index(after: next)
                    continue
                } else if character == "\"" {
                    quoted = false
                } else {
                    field.append(character)
                }
            } else if character == "\"" && field.isEmpty {
                quoted = true
            } else if character == "," {
                row.append(field)
                field.removeAll(keepingCapacity: true)
            } else if character == "\n" {
                row.append(field.hasSuffix("\r") ? String(field.dropLast()) : field)
                result.append(row)
                guard result.count <= maximumRows else { throw ChromeCSVImportError.tooManyRows }
                row.removeAll(keepingCapacity: true)
                field.removeAll(keepingCapacity: true)
            } else {
                field.append(character)
            }
            index = next
        }
        guard !quoted else { throw ChromeCSVImportError.malformedCSV }
        if !field.isEmpty || !row.isEmpty {
            row.append(field)
            result.append(row)
        }
        guard result.count <= maximumRows else { throw ChromeCSVImportError.tooManyRows }
        return result
    }

    private static func value(at index: Int, in row: [String]) -> String {
        row.indices.contains(index) ? row[index] : ""
    }
}
