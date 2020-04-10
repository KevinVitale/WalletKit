import BIP32
import Base58

public protocol CoinType {
    static var id     :UInt32 { get }
    static var symbol :String { get }
    
    static func privateKey(from extendedKey: ExtendedKey) -> String
    static func publicKey(from extendedKey: ExtendedKey) throws -> String
}

public struct BTC: CoinType {
    public static var id     :UInt32 = 00
    public static var symbol :String = "BTC"
    
    public static func privateKey(from extendedKey: ExtendedKey) -> String {
        extendedKey.key.hexString
    }
    
    public static func publicKey(from extendedKey: ExtendedKey) throws-> String {
        return try extendedKey.publicKey().key.hexString
    }
}

public struct ETH: CoinType {
    public static var id     :UInt32 = 60
    public static var symbol :String = "ETH"
    
    public static func privateKey(from extendedKey: ExtendedKey) -> String {
        "0x" + extendedKey.key.dropFirst().hexString
    }
    
    public static func publicKey(from extendedKey: ExtendedKey) throws-> String {
        try extendedKey.publicKey().key.hexString
    }
}

public struct Testnet: CoinType {
    public static var id     :UInt32 = 01
    public static var symbol :String = ""
    
    public static func privateKey(from extendedKey: ExtendedKey) -> String {
        extendedKey.key.hexString
    }
    
    public static func publicKey(from extendedKey: ExtendedKey) throws-> String {
        try extendedKey.publicKey().key.hexString
    }
}
