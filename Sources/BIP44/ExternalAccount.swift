import Foundation
import BIP32

public struct ExternalAccount<Coin: CoinType>: Account, LazyCollectionProtocol {
    public typealias Index = KeyIndex
    
    public init(rootKey: ExtendedKey) throws {
        self.rootKey = rootKey
    }

    public let rootKey: ExtendedKey
    
    public var startIndex : Index { .min }
    public var endIndex   : Index { .max  }
    
    public func index(after i: Index) -> Index {
        i.index(after: i)
    }
    
    public subscript(position: Index) -> ExternalAccount<Coin> {
        try! .init(rootKey: try! rootKey
            .privateKey(atIndex: .normal(0))
            .privateKey(atIndex: position))
    }
    
    public subscript(bounds: Range<KeyIndex>) -> Slice<ExternalAccount<Coin>> {
        Slice<ExternalAccount<Coin>>.init(base: self, bounds: bounds)
    }
}

extension ExternalAccount: CustomStringConvertible {
    public var description: String {
        self.rootKey.description
    }
    
    public var pathURL: URL {
        self.rootKey.pathURL
    }
}
