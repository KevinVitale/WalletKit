import CryptoCore
import BigInt

public protocol KeyDerivator {
    @inlinable
    static func hmac<H: HashFunction>(_ hashFunction: H.Type, key: Data, data: Data) -> Result<Data, KeyDerivatorError>
    
    @inlinable
    static func secp256k_1(data: Data, compressed: Bool) -> Result<Data, KeyDerivatorError>
    
    @inlinable
    static func hash160(data: Data) -> Result<Data, KeyDerivatorError>
}

/**
 * Default implementations of protocol functions.
 */
extension KeyDerivator {
    @inlinable @inline(__always)
    public static func hmac<H>(_ hashFunction: H.Type, key: Data, data: Data) -> Result<Data, KeyDerivatorError> where H : HashFunction {
        .success({
            var hmac = HMAC<H>(key: SymmetricKey(data: key))
            hmac.update(data: data)
            return Data(hmac.finalize())
            }()
        )
    }

    @inlinable @inline(__always)
    public static func secp256k_1(data: Data, compressed: Bool) -> Result<Data, KeyDerivatorError> {
        _GeneratePublicKey(data: data, compressed: compressed)
    }
    
    @inlinable @inline(__always)
    public static func hash160(data: Data) -> Result<Data, KeyDerivatorError> {
        .success(
            RIPEMD160.hash(data: {
                var sha256 = SHA256()
                sha256.update(data: data)
                return Data(sha256.finalize())
            }())
        )
    }
    
    @inlinable @inline(__always)
    public static func doubleSHA256(data: Data) -> Result<Data, KeyDerivatorError> {
        let sha256Hash = { (data: Data) -> Data in
            var hash = SHA256()
            hash.update(data: data)
            return Data(hash.finalize())
        }
        
        return .success( sha256Hash(sha256Hash(data)) )
    }
}

/**
 * The total number of possible extended keypairs is almost 2512, but the
 * produced keys are only 256 bits long, and offer about half of that in
 * terms of security. Therefore, master keys are not generated directly,
 * but instead from a potentially short seed value.
 *
 * - BIP-0032 : https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation
 */
extension KeyDerivator {
    static func masterKeyData(fromSeed data: Data) -> Result<(key: Data, chainCode: Data), KeyDerivatorError> {
        hmac(SHA512.self, key: .BitcoinKeyData, data: data).map { ($0[..<32], $0[32...]) }
    }
}

/**
 *
 */
public enum KeyDerivatorError: Swift.Error {
    case keyDerivationError(Swift.Error)
    case missingImplementation
    case keyDerivationFailed(_ description: String)
}

//------------------------------------------------------------------------------
extension Data {
    /**
     * `public` is used to allow functions to be inlined.
     */
    public static let BitcoinKeyData = try! Data(hexString: "426974636f696e2073656564") // key = "Bicoin seed"
}

//------------------------------------------------------------------------------
/**
 * 65-bytes if `compressed`; 33-bytes, otherwise.
 */
@usableFromInline
func _GeneratePublicKey(data: Data, compressed: Bool) -> Result<Data, KeyDerivatorError> {
    guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) else {
        return .failure(.keyDerivationFailed("Failed to generate a public key: invalid context."))
    }
    
    defer { secp256k1_context_destroy(ctx) }
    
    do {
        var privateKey: [UInt8] = Array(data)
        let publicKey  = try _CreatePublicKey(ctx: ctx, &privateKey)
        let pubKeyData = try _SerializePublicKey(ctx: ctx, publicKey: publicKey, compressed: compressed)
        return .success(pubKeyData)
    }
    catch let error as KeyDerivatorError {
        return .failure(error)
    }
    catch {
        return .failure(.keyDerivationError(error))
    }
}

func _CreatePublicKey(ctx: OpaquePointer, _ data: inout [UInt8]) throws -> UnsafeMutablePointer<secp256k1_pubkey> {
    guard secp256k1_ec_seckey_verify(ctx, data) == 1 else {
        throw KeyDerivatorError.keyDerivationFailed("Failed to generate a public key: invalid secret key.")
    }
    
    let publicKey = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity: 1)
    guard secp256k1_ec_pubkey_create(ctx, publicKey, data) == 1 else {
        throw KeyDerivatorError.keyDerivationFailed("Failed to generate a public key: invalid context.")
    }
    
    return publicKey
}

func _SerializePublicKey(ctx: OpaquePointer, publicKey: UnsafeMutablePointer<secp256k1_pubkey>, compressed: Bool) throws -> Data {
    let compress       = compressed ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)
    let outputByteSize = compressed ? 33 : 65
    var publicKeyBytes = [UInt8](repeating: 0, count: outputByteSize)
    var publicKeyLen   = publicKeyBytes.count
    
    guard secp256k1_ec_pubkey_serialize(ctx, &publicKeyBytes, &publicKeyLen, publicKey, compress) == 1 else {
        throw KeyDerivatorError.keyDerivationFailed("Failed to generate a public key: public key could not be serialized.")
    }
    return Data(publicKeyBytes)
}

//------------------------------------------------------------------------------
#if canImport(CryptoKit)
import CryptoKit
/**
 * An implementation of `KeyDerivator` using _CryptoKit_.
 */
public struct CryptoKitKeyDerivator: KeyDerivator {
    /**
     * _CryptoKit_ & _SwiftCrypto_ share the same APIs.
     */
}
#endif

//------------------------------------------------------------------------------
#if canImport(Crypto)
import Crypto
/**
 * An implementation of `KeyDerivator` using _SwiftCrypto_.
 */
public struct SwiftCryptoKeyDerivator: KeyDerivator {
    /**
     * _CryptoKit_ & _SwiftCrypto_ share the same APIs.
     */
}
#endif

//------------------------------------------------------------------------------
#if     canImport(CryptoKit)
public typealias DefaultKeyDerivator = CryptoKitKeyDerivator
#elseif canImport(Crypto)
public typealias DefaultKeyDerivator = SwiftCryptoKeyDerivator
#endif

