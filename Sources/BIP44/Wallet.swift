import Foundation
import BIP39
import BIP32

public struct Wallet<Coin: CoinType> {
    public init(withRootKey rootKey: ExtendedKey) {
        self.rootKey = rootKey
    }
    
    public var rootKey: ExtendedKey
    
    public func account(atIndex index: UInt32, change internal: Bool = false) throws -> some Account {
        switch `internal` {
        case false:
            return try ExternalAccount<Coin>(rootKey: try self.rootKey
                .privateKey(atIndex: .hardened(44))
                .privateKey(atIndex: .hardened(Coin.id))
                .privateKey(atIndex: .hardened(index))
            )
        case true:
            fatalError("Not implemented yet (\"InternalAccount<Coin>\")")
        }
    }
}

extension Wallet {
    public init(seedPhrase phrase: String, passphrase: String = "", seedDerivator: SeedDerivator.Type = DefaultSeedDerivator.self, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        let mnemonic = try Mnemonic(seedPhrase: phrase)
        try self.init(mnemonic: mnemonic, passphrase: passphrase, version: .mainnet(.private), seedDerivator: seedDerivator, using: keyDerivator)
    }

    public init(mnemonic: Mnemonic, passphrase: String = "", version network: Network, seedDerivator: SeedDerivator.Type = DefaultSeedDerivator.self, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        let rootKey = mnemonic.rootKey(passphrase: passphrase, version: network, seedDerivator: seedDerivator, using: keyDerivator)
        self.init(withRootKey: try rootKey.get())
    }
    
    public init(seedData seed: Data, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        let rootKey = try ExtendedKey(seedData: seed, version: .mainnet(.private), using: keyDerivator)
        self.init(withRootKey: rootKey)
    }
    
    public init(seedHexString seed: String, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        let rootKey = try ExtendedKey(seedData: try Data(hexString: seed), version: .mainnet(.private), using: keyDerivator)
        self.init(withRootKey: rootKey)
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
