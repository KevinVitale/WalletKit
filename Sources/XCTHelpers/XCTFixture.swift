import Foundation

public struct XCTFixture<JSON: Decodable> {
    public enum Error: Swift.Error {
        case fileNotFound(String)
    }

    private let _fileURL: URL
    
    public init(fileNamed name: String) throws {
        let file = "file://\(#file)"
        let urlB = URL(string: file)?.deletingLastPathComponent()
        
        guard let url = urlB?.appendingPathComponent(name) else {
            throw Error.fileNotFound(name)
        }
        
        self._fileURL = url
    }
    
    public func loadTests() throws -> JSON {
        let decoder  = JSONDecoder()
        let jsonData = try Data(contentsOf: self._fileURL)
        return try decoder.decode(JSON.self, from: jsonData)
    }
}

public protocol XCTFixtureProvider: Decodable {
    static var fileName: String { get }
}

extension XCTFixture where JSON: XCTFixtureProvider {
    public static func loadTests() throws -> JSON {
        try XCTFixture(fileNamed: JSON.fileName).loadTests()
    }
}

