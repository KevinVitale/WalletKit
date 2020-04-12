import Foundation
import BIP39
import BIP32

public struct Wallet<Coin: CoinType> {
    public init(withRootKey rootKey: ExtendedKey) {
        self.rootKey = rootKey
    }
    
    public var rootKey: ExtendedKey
}

extension Wallet {
    private struct Account: BIP44.Account {
        init(privateKey: ExtendedKey, isExternal: Bool) throws {
            self.privateKey = privateKey
            self.isExternal = isExternal
            self.address    = try Coin.address(from: privateKey)
        }
        
        let address     :String
        let isExternal  :Bool
        let privateKey  :ExtendedKey
    }
    
    public func account(atIndex index: UInt32, isExternal external: Bool = true) throws -> some BIP44.Account {
        return try Account(privateKey: try self.rootKey
                            .privateKey(atIndex: .hardened(44))
                            .privateKey(atIndex: .hardened(Coin.id))
                            .privateKey(atIndex: .hardened(index)),
                           isExternal: external)
    }
}

extension Wallet {
    public init<Entropy: EntropyGenerator>(entropy: Entropy, passphrase: String = "", version network: Network, seedDerivator: SeedDerivator.Type = DefaultSeedDerivator.self, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        self = try Mnemonic(entropy: entropy)
            .rootKey(passphrase    :passphrase,
                     version       :network,
                     seedDerivator :seedDerivator,
                     using         :keyDerivator)
            .map(Wallet.init)
            .get()
    }

    public init(seedData seed: Data, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        let rootKey = try ExtendedKey(seedData: seed, version: .mainnet(.private), using: keyDerivator)
        self.init(withRootKey: rootKey)
    }
    
    public init(seedHexString seed: String, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        try self.init(seedData: try Data(hexString: seed), using: keyDerivator)
    }
}

extension Wallet: CustomStringConvertible {
    public var description: String {
        rootKey.description
    }
}

extension ExtendedKey {
    public static func ==<Coin: CoinType>(lhs: ExtendedKey, rhs: Wallet<Coin>) -> Bool {
        lhs.description == rhs.description
    }
    
    public static func ==<Coin: CoinType>(lhs: Wallet<Coin>, rhs: ExtendedKey) -> Bool {
        rhs == lhs
    }
}
