import BIP39
import BIP32

extension Mnemonic {
    public func rootKey(passphrase: String = "", version network: Network, seedDerivator: SeedDerivator.Type = DefaultSeedDerivator.self, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) -> Result<ExtendedKey, KeyDerivatorError> {
        self.seed(passphrase: passphrase, derivator: seedDerivator)
            .mapError { KeyDerivatorError.keyDerivationError($0) }
            .flatMap { masterSeed in
                Result {
                    try ExtendedKey(seedData: masterSeed, version: network, using: keyDerivator)
                }
                .mapError { KeyDerivatorError.keyDerivationError($0) }
        }
    }

    public func wallet<Coin: CoinType>(passphrase: String = "", seedDerivator: SeedDerivator.Type = DefaultSeedDerivator.self, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) -> Result<Wallet<Coin>, KeyDerivatorError> {
        rootKey(passphrase: passphrase, version: .mainnet(.private), seedDerivator: seedDerivator, using: keyDerivator).map(Wallet.init)
    }
    
    public func wallet<Coin: CoinType>(coinType: Coin.Type, passphrase: String = "", seedDerivator: SeedDerivator.Type = DefaultSeedDerivator.self, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) -> Result<Wallet<Coin>, KeyDerivatorError> {
        wallet(passphrase: passphrase, seedDerivator: seedDerivator, using: keyDerivator)
    }
}
