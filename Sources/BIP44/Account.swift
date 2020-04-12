import Foundation
import BIP32

public protocol Account: LazyCollectionProtocol where Element == Self, Index == KeyIndex {
    associatedtype Coin: CoinType
    
    var isExternal :Bool        { get }
    var privateKey :ExtendedKey { get }
    var address    :String      { get }

    init(privateKey: ExtendedKey, isExternal: Bool) throws
}

extension Account {
    public var address     :String { try! Coin.address(from: self.privateKey) }
    public var pathURL     :URL    { self.privateKey.pathURL }
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
        try! Self.init(privateKey: try! privateKey
            .privateKey(atIndex: isExternal ? .normal(0) : .normal(1))
            .privateKey(atIndex: position), isExternal: self.isExternal)
    }
}

