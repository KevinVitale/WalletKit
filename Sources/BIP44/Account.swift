import Foundation
import BIP32

public protocol Account: CustomStringConvertible, Collection where Element == Self, Index == KeyIndex {
    associatedtype Coin: CoinType
    
    var pathURL :URL         { get }
    var rootKey :ExtendedKey { get }
    
    init(rootKey: ExtendedKey) throws
}

extension Account {
    public var privateKey: String {
        Coin.privateKey(from: self.rootKey)
    }
    
    public var publicKey: String {
        try! Coin.publicKey(from: self.rootKey)
    }
}
