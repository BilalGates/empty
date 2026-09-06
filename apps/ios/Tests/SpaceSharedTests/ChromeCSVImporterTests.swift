import Foundation
import XCTest
@testable import SpaceShared

final class ChromeCSVImporterTests: XCTestCase {
    func testParsesQuotedChromeCSVAndDeduplicatesLocally() throws {
        let csv = "\u{feff}name,url,username,password\nExample,https://example.com/login,user,pw\n\"Example, Inc\",https://example.com,user,pw"
        let result = try ChromeCSVImporter.parse(data: Data(csv.utf8))
        XCTAssertEqual(result.accepted.count, 1)
        XCTAssertEqual(result.duplicates, 1)
        XCTAssertEqual(result.accepted.first?.serviceIdentifier, "https://example.com")
    }

    func testRejectsUnsafeAndMalformedRowsWithoutRejectingValidRows() throws {
        let csv = "name,url,username,password\nUnsafe,http://example.com,u,p\nMissing,https://valid.example,u,\nValid,https://valid.example,u,p"
        let result = try ChromeCSVImporter.parse(data: Data(csv.utf8))
        XCTAssertEqual(result.accepted.count, 1)
        XCTAssertEqual(result.issues.map(\.row), [2, 3])
    }

    func testRejectsOversizedInputBeforeParsing() {
        XCTAssertThrowsError(
            try ChromeCSVImporter.parse(data: Data(count: ChromeCSVImporter.maximumFileSize + 1))
        ) { error in
            XCTAssertEqual(error as? ChromeCSVImportError, .oversized)
        }
    }

    func testRejectsUnterminatedQuotedField() {
        XCTAssertThrowsError(
            try ChromeCSVImporter.parse(data: Data("name,url,username,password\n\"bad".utf8))
        ) { error in
            XCTAssertEqual(error as? ChromeCSVImportError, .malformedCSV)
        }
    }
}
