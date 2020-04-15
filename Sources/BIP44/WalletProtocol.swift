import Foundation
import BIP39
import BIP32

public protocol WalletProtocol {
    init(withRootKey rootKey: ExtendedKey)
    
    var rootKey: ExtendedKey { get }
}

extension WalletProtocol {
    public func account(coinType: AnyCoinType, atIndex index: KeyIndex.RawValue, isExternal external: Bool = true) throws -> some AccountProtocol {
        try Account(
            coinType: coinType,
            privateKey: try self.rootKey
                .privateKey(atIndex: .hardened(44))
                .privateKey(atIndex: .hardened(coinType.id))
                .privateKey(atIndex: .hardened(index)),
            isExternal: external
        )
    }
}

struct Wallet: WalletProtocol {
    init(withRootKey rootKey: ExtendedKey) {
        self.rootKey = rootKey
    }
    
    let rootKey: ExtendedKey
}

enum WalletError: Error {
    /// If the _network_ associated with `rootKey` is not _private_.
    case rootKeyIsNotPrivate
}
