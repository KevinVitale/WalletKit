import Foundation
import BIP32

public protocol Account: LazyCollectionProtocol, CustomStringConvertible where Element == Self, Index == KeyIndex {
    associatedtype Coin: CoinType
    
    var pathURL    :URL         { get }
    var rootKey    :ExtendedKey { get }
    var isExternal :Bool        { get }
    
    init(rootKey: ExtendedKey, isExternal: Bool) throws
}

extension Account {
    public var description: String {
        self.rootKey.description
    }
    
    public var address: String {
        try! Coin.address(from: self.rootKey)
    }
    
    public var pathURL: URL {
        self.rootKey.pathURL
    }
}

extension Account {
    public var startIndex : Index { .min }
    public var endIndex   : Index { .max }
    
    public func index(after i: Index) -> Index {
        i.index(after: i)
    }
    
    public subscript(bounds: Range<KeyIndex>) -> Slice<Self> {
        Slice<Self>.init(base: self, bounds: bounds)
    }
    
    public subscript(position: Index) -> Self {
        try! Self.init(rootKey: try! rootKey
            .privateKey(atIndex: isExternal ? .normal(0) : .normal(1))
            .privateKey(atIndex: position), isExternal: self.isExternal)
    }
}
