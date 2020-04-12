import BIP32
import Base58

public protocol CoinType {
    static var id     :UInt32 { get }
    static var symbol :String { get }
    
    static func address(from privateKey: ExtendedKey) throws -> String
}

public struct BTC: CoinType {
    public static var id     :UInt32 = 00
    public static var symbol :String = "BTC"
    
    public static func address(from privateKey: ExtendedKey) throws-> String {
        return try privateKey.publicKey().key.hexString
    }
    
    public struct Testnet: CoinType {
        public static var id     :UInt32 = 01
        public static var symbol :String = ""
        
        public static func address(from privateKey: ExtendedKey) throws-> String {
            try BTC.address(from: privateKey)
        }
    }
}

public struct ETH: CoinType {
    public static var id     :UInt32 = 60
    public static var symbol :String = "ETH"
    
    public static func address(from privateKey: ExtendedKey) throws -> String {
        try DefaultKeyDerivator
            .secp256k_1(data: privateKey.key.dropFirst(), compressed: false)
            .map { "0x" + $0.dropFirst().keccak256.suffix(20).hexString }
            .get()
    }
}
