import CryptoCore
import BigInt

/**
 * An extended key, as specified by **BIP32**.
 *
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
public struct ExtendedKey {
    /**
     * Crate a _root key_ from `masterSeed`.
     *
     * - parameter masterSeed   :
     * - parameter network      :
     * - parameter keyDerivator :
     */
    public init(seedData masterSeed: Data, version network: Network, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        self = try keyDerivator
            .masterKeyData(fromSeed: masterSeed)
            .flatMap({ masterKey in
                Result {
                    try ExtendedKey.init(
                        pathURL     :URL(string: "m")!,
                        depth       :0,
                        version     :network,
                        fingerprint :0,
                        index       :.normal(0),
                        chainCode   :masterKey.chainCode,
                        key         : network.sector == .private ? [0x00] + masterKey.key : try keyDerivator.secp256k_1(data: masterKey.key, compressed: true).get()
                    )
                }
                .mapError({ .keyDerivationError($0) })
            })
            .get()
    }
    
    /**
     * Crate a _root key_ from `masterSeed`.
     *
     * - parameter masterSeed   :
     * - parameter network      :
     * - parameter keyDerivator :
     */
    public init(seedHexString masterSeed: String, version network: Network, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        try self.init(seedData: try Data(hexString: masterSeed), version: network, using: keyDerivator)
    }

    /// Encoded _serialized data_ in Base58, by first adding 32 checksum bits
    /// (derived from the double SHA-256 checksum), then converting to Base58.
    private let _description: String
    
    /// Extended keys wrap around their serialized data form.
    private let _serializedKey: Data
    
    /// The path of the extended key's derivation.
    public private(set) var pathURL: URL
}

extension ExtendedKey: CustomStringConvertible {
    /**
     * Create an _extended key_.
     *
     * - parameter depth        :
     * - parameter network      :
     * - parameter fingerprint  :
     * - parameter index        :
     * - parameter chainCode    :
     * - parameter key          :
     * - parameter keyDerivator :
     */
    private init(pathURL: URL, depth: UInt8, version network: Network, fingerprint: UInt32, index: KeyIndex, chainCode: Data, key: Data) throws {
        let serializedKey: Data = {
            var data = Data(capacity: 78)
            
            data += network.bytes
            data += depth.bytes
            data += fingerprint.bytes
            data += index.bytes
            data += chainCode
            data += key
            
            return data
        }()
        
        guard case 77...78 = serializedKey.count else {
            throw Error.invalidSerializedKey(serializedKey)
        }
        
        self._serializedKey = serializedKey
        self._description = { // Compute the Base58 representation of the key.
            func sha256(from data: Data) -> Data {
                var sha256 = SHA256()
                sha256.update(data: data)
                return Data(sha256.finalize())
            }
            
            let checksum = sha256(from: sha256(from: serializedKey))[..<4]
            return Base58.encode(serializedKey + checksum)
        }()
        self.pathURL = pathURL
    }
    
    /// Base58-encoded description.
    public var description: String {
        _description
    }
}

extension ExtendedKey {
    /**
     * The function of an _child extended key_.
     */
    public enum Derivation {
        /// Defined as: `CKDpriv((kp, cp), i) -> (ki, ci)`.
        ///
        /// The `at` index can be either `normal` or `hardened`.
        ///
        /// - note: If a parent public extended key attempts to derive a private
        ///         child extended key, an exception will be thrown as this is
        ///         logically not possible.
        case toPrivateKey(at: KeyIndex)
        
        /// Defined as: `CKDpub((Kp, cp), i) -> (Ki, ci)`.
        ///
        /// ISSUES #1: https://github.com/KevinVitale/WalletKit/issues/1
        ///
        /// - note: If a parent public extended key attempts to derive a public
        ///         child extended key, an exception will be thrown because I'm
        ///         a complete idiot, and can figure it out.
        case toPublicKey(at: KeyIndex)
        
        /// The _child extended key_'s index.
        fileprivate var index: KeyIndex {
            switch self {
            case .toPrivateKey(let index): return index
            case .toPublicKey(let index): return index
            }
        }
        
        /// An implied value; suggests the derived _child extended key_ is public or private.
        fileprivate var sector: Sector {
            switch self {
            case .toPublicKey  :return .public
            case .toPrivateKey :return .private
            }
        }
        
        /**
         * For a given `Derivation` enum case (either `toPrivateKey(at:)`, or
         * `toPublicKey(at:)`) calling this will construct the function for which
         * a `key` and `chainCode` can be derived for a given `ExtendedKey`.
         *
         * - parameter keyDerivator: The type of key derivator to use.
         * - returns: A function which performs derivation for a given `ExtendedKey`.
         */
        fileprivate func perform(using keyDerivator: KeyDerivator.Type) -> (_ with: ExtendedKey) throws -> (key: Data, chainCode: Data) {
            let hmac512 = { (chainCode: Data, data: Data) -> Result<(Data,Data), KeyDerivatorError> in
                keyDerivator
                    .hmac(SHA512.self, key: chainCode, data: data)
                    .map({ ($0[..<32],$0[32...]) })
            }
            
            switch self {
            case .toPrivateKey(let index): /* To: Private-Key */
                return { parent in
                    func computeChildKey(key: Data, chainCode: Data) -> (key: Data, chainCode: Data) {
                        // TODO: Sanity-check 'BigUInt'
                        var childKeyNum = BigUInt(parent.key)
                        childKeyNum    += BigUInt(key)
                        childKeyNum    %= .CurveOrder
                        
                        let numData  = childKeyNum.serialize()
                        var childKey = Data(repeating: 0, count: 33)
                        childKey[max(1, (33-numData.count))...] = numData
                        
                        return (key: childKey, chainCode: chainCode)
                    }
                    
                    switch parent.network.sector {
                    /// 'private' -> 'private'
                    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
                    case .private where index.isHardened:
                        // 'parent.key' includes 0x00
                        let (key, chainCode) = try hmac512(parent.chainCode, parent.key + index.bytes).get()
                        return computeChildKey(key: key, chainCode: chainCode)
                        
                    case .private where !index.isHardened:
                        // 'parent.key' drops 0x00
                        let pKey = try keyDerivator.secp256k_1(data: parent.key.dropFirst(), compressed: true).get()
                        let (key, chainCode) = try hmac512(parent.chainCode, pKey + index.bytes).get()
                        return computeChildKey(key: key, chainCode: chainCode)

                    /* ------------------------------------------------------ */
                    /// 'public' -> 'private'
                    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--private-child-key
                    default:
                        throw Error.invalidDerivation(to: self, from: parent)
                    }
            }
            case .toPublicKey(let index): /* To: Public-Key */
                return { parent in
                    switch parent.network.sector {
                    /// 'private' -> 'public'
                    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--public-child-key
                    case .private:
                        let result   = try Derivation.toPrivateKey(at: index).perform(using: keyDerivator)(parent)
                        let childKey = try keyDerivator.secp256k_1(data: result.key.dropFirst(), compressed: true).get()
                        
                        return (key: childKey, chainCode: result.chainCode)
                        
                    /// 'public' -> 'public:non-hardened'
                    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
                    case .public where !index.isHardened:
                        throw Error.tooStupidToFigureOutPublicToPublicDerivation

                    /* ------------------------------------------------------ */
                    /// 'public' -> 'public:hardened'
                    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
                    default:
                        throw Error.invalidDerivation(to: self, from: parent)
                    }
                }
            }
        }
    }
    
    /**
     * Contructs a new _extended child key_ for the given `derivation`.
     *
     * - parameter derivation   : The type of _child extended key_ to derive.
     * - parameter keyDerivator : The type of `KeyDerivator` to use.
     *
     * - returns: A new `ExtendedKey` at the `KeyIndex` associated with `derivation`.
     */
    private func derive(_ derivation: Derivation, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> ExtendedKey {
        let (key, chainCode) = try derivation.perform(using: keyDerivator)(self)
        
        // Attempt to generate the next `depth`.
        let nextDepth = try depth.nextDepth().wrappedValue

        // Generate the child's `fingerprint` from the `parent`.
        let fingerprint: UInt32 = UInt32(data: try keyDerivator.hash160(data: try publicKey().key).get()[...3])!
        
        // Instantiate the `childKey`.
        return try ExtendedKey(
            pathURL     :pathURL.appendingPathComponent(derivation.index.description),
            depth       :nextDepth,
            version     :network.switched(to: derivation.sector),
            fingerprint :fingerprint,
            index       :derivation.index,
            chainCode   :chainCode,
            key         :key
        )
    }
}

extension ExtendedKey {
    /**
     * The key converted to public key. If this key is already public, `self` is
     * returned.
     *
     * - parameter keyDerivator: The type of `KeyDerivator` to use.
     */
    public func publicKey(using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> ExtendedKey {
        guard case .private = network.sector else {
            return self
        }
        
        return try ExtendedKey(
            pathURL     : pathURL,
            depth       : depth.wrappedValue,
            version     : network.switched(to: .public),
            fingerprint : fingerprint,
            index       : index,
            chainCode   : chainCode,
            key         : try keyDerivator.secp256k_1(data: key.dropFirst(), compressed: true).get()
        )
    }
    
    /**
     * Attempts to create a _public child extended key_ at `index`.
     *
     * - parameter index        : Where the new key should be derived at.
     * - parameter keyDerivator : The type of `KeyDerivator` to use.
     *
     * - returns: A new _private child_ `ExtendedKey` at `index`.
     */
    public func privateKey(atIndex index: KeyIndex) throws -> ExtendedKey {
        try derive(.toPrivateKey(at: index))
    }
    
    /**
     * Attempts to create a _public child extended key_ at `index`.
     *
     * - parameter index        : Where the new key should be derived at.
     * - parameter keyDerivator : The type of `KeyDerivator` to use.
     *
     * - warning: Although both _normal_ or _hardened_ indexes are valid inputs
     *            for this function, a public parent key cannot derive a hardened
     *            public child key, and an attempt to do so throws an exception.
     *
     * - returns: A new _private child_ `ExtendedKey` at `index`.
     */
    public func publicKey(atIndex index: KeyIndex) throws -> ExtendedKey {
        try derive(.toPublicKey(at: index))
    }
}

extension ExtendedKey {
    /// The network version.
    ///
    /// Either `mainnet` or `testnet`, and either a _public_ or _private_ key.
    ///
    /// - note: Networks are specified as being either _public_ or _private_,
    ///         (`Sector`), which also corresponds to this keys own `sector`.
    public var network: Network {
        Network(data: _serializedKey[...3])!
    }
    
    /// The key's depth.
    /// - note: Root (_master_) keys have `0x00` depth.
    public var depth: KeyDepth {
        KeyDepth(wrappedValue: _serializedKey[4])
    }
    
    /// The key's index.
    /// - note: Root (_master_) keys have a `0x00000000` fingerprint.
    public var fingerprint: UInt32 {
        UInt32(data: _serializedKey[5...8])!
    }
    
    /// The key's index.
    ///
    /// Hardened extended keys start at `0x80000000`.
    ///
    /// - note: Root (_master_) keys have a `0x00000000` index.
    public var index: KeyIndex {
        KeyIndex(rawValue: UInt32(data: _serializedKey[9...12])!)
    }
    
    /// An extra 256 bits of entropy that is identical for private/public key pairs.
    public var chainCode: Data {
        _serializedKey[13...44]
    }
    
    /// The public of private 33-byte key data.
    /// - note: A private key will be padded with a single zero-byte prefix
    ///         during initialization.
    public var key: Data {
        _serializedKey[45...]
    }
}

extension ExtendedKey: Equatable {
    public static func ==(lhs: ExtendedKey, rhs: ExtendedKey) -> Bool {
        lhs._serializedKey == rhs._serializedKey
    }
    
    public static func ==(lhs: ExtendedKey, rhs: String) -> Bool {
        lhs.description == rhs
    }
}

/**
 * `ExtendedKey` errors which may occur.
 */
extension ExtendedKey {
    public enum Error: Swift.Error {
        /// Thrown when a _child_ derivation from a _parent_ is not feasible.
        /// - note: This error will be thrown if `from` is _public_, and `to` is _private_.
        case invalidDerivation(to: ExtendedKey.Derivation, from: ExtendedKey)

        /// Catches failures on extended key created with malformed data.
        case invalidSerializedKey(Data)
        
        case tooStupidToFigureOutPublicToPublicDerivation
        
        /// Catches over all errors. Good luck! ¯\_(ツ)_/¯
        case unknown(Swift.Error)
    }
}

extension BigUInt {
    /// Modulo constant (referred to a `n` in **BIP32** spec) used for
    /// calculating extended private keys.
    static let CurveOrder: BigUInt = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
    static let PointG    : BigUInt = BigUInt("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", radix: 16)!
}

