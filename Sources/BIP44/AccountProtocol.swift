import Foundation
import BIP32

public protocol AccountProtocol: LazyCollectionProtocol where Element == Self, Index == KeyIndex {
    associatedtype Coin: CoinType
    
    init(coinType: Coin, privateKey: ExtendedKey) throws
    
    var address    :String      { get }
    var coinType   :Coin        { get }
    var privateKey :ExtendedKey { get }
}

extension AccountProtocol {
    public var pathURL: URL {
        self.privateKey.pathURL
    }

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
            privateKey: try! self.privateKey.privateKey(atIndex: position)
        )
    }
}

struct Account: AccountProtocol {
    typealias Index = KeyIndex
    init(coinType: AnyCoinType, privateKey: ExtendedKey) throws {
        self.address    = try coinType.address(for: privateKey)
        self.coinType   = coinType
        self.privateKey = privateKey
    }
    
    let address    :String
    let coinType   :AnyCoinType
    let privateKey :ExtendedKey
}

