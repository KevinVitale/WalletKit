import CryptoCore

public protocol SeedDerivator {
    /**
     * Derives a seed (_mnemonic secret key_) from a password and salt using _PBKDF2_.
     *
     * - Wikipedia: https://en.wikipedia.org/wiki/PBKDF2
     * - BIP-0039: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
     *
     * This seed can be later used to generate deterministic wallets using
     * `BIP-0032` or similar methods.
     */
    @inlinable
    static func derivedSeed(fromPassword password: String, salt: String) -> Result<Data, SeedDerivatorError>
}

/**
 * Errors relating to `SeedDerivatorError`.
 */
public enum SeedDerivatorError: Swift.Error {
    case seedDerivationFailed
    case seedPhraseInvalid(String)
    case error(Swift.Error)
}

//------------------------------------------------------------------------------
#if canImport(CommonCrypto)
import CommonCrypto
/**
 * Seed derivator using `CommonCrypto` implementation of _PBKDF2_.
 *
 * https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60118.50.1/include/CommonKeyDerivation.h.auto.html
 */
public struct CommonCryptoSeedDerivator: SeedDerivator {
    @inlinable @inline(__always)
    public static func derivedSeed(fromPassword password: String, salt: String) -> Result<Data, SeedDerivatorError> {
        var _password      = password.data(using: .utf8)!.map(Int8.init)
        let _passwordCount = password.count
        
        var _salt      = salt.data(using: .utf8)!.map({ $0 })
        let _saltCount = salt.count
        
        var data = [UInt8](repeating: 0, count: 64)

        let status = CCKeyDerivationPBKDF( CCPBKDFAlgorithm(kCCPBKDF2),
            &_password, _passwordCount,
            &_salt, _saltCount,
            CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512),
            2048,
            &data,
            data.count)
        
        /**
         * `kCCParamError` can result from bad values for the password, salt,
         * and unwrapped key pointers as well as a bad value for the prf
         * function.
         */
        guard status == kCCSuccess else {
            return .failure(.seedDerivationFailed)
        }
        
        return .success(Data(data))
    }
}
#endif

//------------------------------------------------------------------------------
#if canImport(CCryptoBoringSSL)
import CCryptoBoringSSL
/**
 * Seed derivator using `BoringSSL` (from _Swift Crypto_) implementation of _PBKDF2_.
 *
 * https://github.com/apple/swift-crypto/blob/master/Sources/CCryptoBoringSSL/crypto/evp/pbkdf.c
 */
public struct BoringSSLSeedDerivator: SeedDerivator {
    @inlinable @inline(__always)
    public static func derivedSeed(fromPassword password: String, salt: String) -> Result<Data, SeedDerivatorError> {
        var _password      = password.data(using: .utf8)!.map(Int8.init)
        let _passwordCount = password.count
        
        var _salt      = salt.data(using: .utf8)!.map({ $0 })
        let _saltCount = salt.count
        
        var data = [UInt8](repeating: 0, count: 64)
        
        let status = CCryptoBoringSSL_PKCS5_PBKDF2_HMAC(
            &_password, _passwordCount,
            &_salt, _saltCount,
            2048,
            CCryptoBoringSSL_EVP_sha512(),
            data.count,
            &data)
        
        guard status == 1 else {
            return .failure(.seedDerivationFailed)
        }
        
        return .success(Data(data))
    }
}
#endif

//------------------------------------------------------------------------------
#if canImport(CryptoSwift)
import CryptoSwift
/**
 * Seed derivator using `CryptoSwift` implementation of _PBKDF2_.
 *
 * https://github.com/krzyzanowskim/CryptoSwift/blob/master/Sources/CryptoSwift/PKCS/PBKDF2.swift
 */
public struct CryptoSwiftSeedDerivator: SeedDerivator {
    @inlinable @inline(__always)
    public static func derivedSeed(fromPassword password: String, salt: String) -> Result<Data, SeedDerivatorError> {
        Result {
            let keyDerivation = try PKCS5.PBKDF2(
                password   :password.data(using: .utf8)!.map(Int8.init),
                salt       :salt.data(using: .utf8)!.map({ $0 }),
                iterations :2048,
                variant    :.sha512
            )
            return Data(try keyDerivation.calculate())
        }
        .mapError {
            .error($0)
        }
    }
}
#endif

//------------------------------------------------------------------------------
/**
 * Seed derivator stub with a missing _PBKDF2_ implementation. Guaranteed to fail.
 */
public struct DummySeedDerivator: SeedDerivator {
    @inlinable @inline(__always)
    public static func derivedSeed(fromPassword password: String, salt: String) -> Result<Data, SeedDerivatorError> {
        return .failure(.seedDerivationFailed)
    }
}

//------------------------------------------------------------------------------
#if     canImport(CommonCrypto)
public typealias DefaultSeedDerivator = CommonCryptoSeedDerivator
#elseif canImport(CCryptoBoringSSL)
public typealias DefaultSeedDerivator = BoringSSLSeedDerivator
#elseif canImport(CryptoSwift)
public typealias DefaultSeedDerivator = CryptoSwiftSeedDerivator
#else
public typealias DefaultSeedDerivator = DummySeedDerivator
#endif

