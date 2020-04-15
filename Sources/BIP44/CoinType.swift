import BIP32
import Base58

public protocol CoinType {
    var id     :UInt32 { get }
    var symbol :String { get }
    
    func address(for privateKey: ExtendedKey, using keyDerivator: KeyDerivator.Type) throws -> String
}

extension CoinType {
    public var index: KeyIndex { .hardened(id) }
}

public struct AnyCoinType: CoinType {
    public let symbol :String
    public let id     :UInt32
    
    public func address(for privateKey: ExtendedKey, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> String {
        switch symbol {
        case "eth", "ETH":
            return try keyDerivator
                .secp256k_1(data: privateKey.key.dropFirst(), compressed: false)
                .map { "0x" + $0.dropFirst().keccak256.suffix(20).hexString }
                .get()
        default:
            return privateKey.key.hexString
        }
    }
}

extension AnyCoinType {
    public static var ETH :AnyCoinType { AnyCoinType(symbol: "ETH", id: 60) }
    public static var BTC :AnyCoinType { AnyCoinType(symbol: "BTC", id: 00) }
    
    public static var TestNet :some CoinType { AnyCoinType(symbol: "", id: 01) }
}
