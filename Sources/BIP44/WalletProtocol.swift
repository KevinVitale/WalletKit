import Foundation
import BIP39
import BIP32

public protocol WalletProtocol {
    init(withRootKey rootKey: ExtendedKey)
    
    var rootKey: ExtendedKey { get }
}

extension WalletProtocol {
  public init(seedData masterSeed: Data, version network: Network, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
    let extendedKey = try ExtendedKey(seedData: masterSeed, version: network, using: keyDerivator)
    self = Self.init(withRootKey: extendedKey)
  }

  public init(seedHexString hexString: String, version network: Network, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
    self = try Self.init(seedData: try Data(hexString: hexString), version: network, using: keyDerivator)
  }
}

extension WalletProtocol {
    public func account(coinType: AnyCoinType, atIndex index: KeyIndex.RawValue, isExternal external: Bool = true) throws -> some AccountProtocol {
        try Account(
            coinType: coinType,
            privateKey: try self.rootKey
                .privateKey(atIndex: .hardened(44))             // Purpose
                .privateKey(atIndex: .hardened(coinType.id))    // Coin
                .privateKey(atIndex: .hardened(index))          // Account
                .privateKey(atIndex: .normal(external ? 0 : 1)) // Change
        )
    }
}

public struct Wallet: WalletProtocol {
    public init(withRootKey rootKey: ExtendedKey) {
        self.rootKey = rootKey
    }
    
    public let rootKey: ExtendedKey
}

enum WalletError: Error {
    /// If the _network_ associated with `rootKey` is not _private_.
    case rootKeyIsNotPrivate
}
