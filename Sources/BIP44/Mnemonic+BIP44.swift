import BIP39
import BIP32

extension Mnemonic {
    public func createWallet(passphrase: String = "", version network: Network = .mainnet(.private), seedDerivator: SeedDerivator.Type = DefaultSeedDerivator.self, keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> some WalletProtocol {
        guard case .private = network.sector else {
            throw WalletError.rootKeyIsNotPrivate
        }
        return try self.seed(passphrase: passphrase, derivator: seedDerivator)
            .mapError({ KeyDerivatorError.keyDerivationError($0) })
            .flatMap({ masterSeed in
                Result {
                    try ExtendedKey(seedData: masterSeed, version: network, using: keyDerivator)
                }
                .mapError { KeyDerivatorError.keyDerivationError($0) }
            })
            .map(Wallet.init)
            .get()
    }
}
