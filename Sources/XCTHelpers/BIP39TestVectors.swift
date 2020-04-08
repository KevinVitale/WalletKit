import Foundation
import BIP39

public struct BIP39TestVectors: XCTFixtureProvider, Decodable, Collection {
    public static var fileName: String = "BIP39TestVectors.json"
    
    enum CodingKeys: String, CodingKey {
        case vocabulary = "english"
    }
    
    public struct Vector: Codable, EntropyGenerator {
        private var _mnemonicPhrase :String = ""
        
        public private(set) var inputEntropy   :String = ""
        public private(set) var binarySeed     :String = ""

        public var words :[String] {
            Array(_mnemonicPhrase.split(separator: " ").map(String.init))
        }
        
        public init(from decoder: Decoder) throws {
            var container = try decoder.unkeyedContainer()
            repeat {
                switch container.currentIndex {
                case 0: self.inputEntropy    = try container.decode(String.self)
                case 1: self._mnemonicPhrase = try container.decode(String.self)
                case 2: self.binarySeed      = try container.decode(String.self)
                default: _ = try container.decode(String.self)
                }
            } while !container.isAtEnd
        }
        
        public func entropy() -> Result<Data, Error> {
            inputEntropy.entropy()
        }
    }
    
    private(set) var vectors :[Vector] = []

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        var nested    = try container.nestedUnkeyedContainer(forKey: .vocabulary)
        repeat {
            self.vectors.append(try nested.decode(Vector.self))
        } while !nested.isAtEnd
    }
    
    public var startIndex :Int { vectors.startIndex }
    public var endIndex   :Int { vectors.endIndex   }
    
    public func index(after i: Int) -> Int {
        vectors.index(after: i)
    }
    
    public subscript(position: Int) -> Vector {
        vectors[position]
    }
}
