import Foundation
import BIP32

public protocol AccountProtocol: LazyCollectionProtocol where Element == Self, Index == KeyIndex {
    associatedtype Coin: CoinType
    
    init(coinType: Coin, privateKey: ExtendedKey, isExternal: Bool) throws
    
    var address    :String      { get }
    var coinType   :Coin        { get }
    var isExternal :Bool        { get }
    var privateKey :ExtendedKey { get }
}

extension AccountProtocol {
    public var pathURL :URL    { self.privateKey.pathURL.appendingPathComponent(changeIndex.description) }
    
    fileprivate var changeIndex :KeyIndex { isExternal ? .normal(0) : .normal(1) }
    
    public var startIndex :Index { .min }
    public var endIndex   :Index { .max }
    
    public func index(after i: Index) -> Index {
        i.index(after: i)
    }
    
    public subscript(bounds: Range<KeyIndex>) -> Slice<Self> {
        Slice<Self>.init(base: self, bounds: bounds)
    }
    
    public subscript(position: Index) -> Self {
        try! Self.init(
            coinType: self.coinType,
            privateKey: try! self.privateKey
                .privateKey(atIndex: changeIndex)
                .privateKey(atIndex: position),
            isExternal: self.isExternal)
    }
}

struct Account: AccountProtocol {
    init(coinType: AnyCoinType, privateKey: ExtendedKey, isExternal: Bool) throws {
        self.address    = try coinType.address(for: privateKey)
        self.coinType   = coinType
        self.privateKey = privateKey
        self.isExternal = isExternal
    }
    
    let address    :String
    let coinType   :AnyCoinType
    let isExternal :Bool
    let privateKey :ExtendedKey
}

