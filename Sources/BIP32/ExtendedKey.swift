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
                        key         :masterKey.key,
                        using       :keyDerivator
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
    private init(pathURL: URL, depth: UInt8, version network: Network, fingerprint: UInt32, index: KeyIndex, chainCode: Data, key: Data, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        let serializedKey: Data = try {
            var data = Data(capacity: 78)
            
            data += network.bytes
            data += depth.bytes
            data += fingerprint.bytes
            data += index.bytes
            data += chainCode
            data += network.sector == .private ? [0x00] + key : try keyDerivator.secp256k_1(data: key, compressed: true).get()
            
            return data
            }()
        
        self = try .init(serializedKey: serializedKey, atPath: pathURL)
    }
    
    /**
     * Create an _extended key_ from a serialized representation, as described
     * in the **BIP32** spec.
     *
     * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
     *
     * - parameter data: The public and private key, in serialized form.
     */
    private init(serializedKey: Data, atPath pathURL: URL) throws {
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
     * The key converted to public key. If this key is already public, `self` is
     * returned.
     */
    public func publicKey() throws -> ExtendedKey {
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
            key         : key.dropFirst() // drop the '0x00'; compute 'pubKey' during 'init'
        )
    }
    
    public func publicKey(atIndex index: UInt32, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> ExtendedKey {
        try extended(.publicKey, atIndex: index, using: keyDerivator)
    }
    
    public func privateKey(atIndex index: KeyIndex, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> ExtendedKey {
        try extended(.privateKey(hardened: index.isHardened), atIndex: index.rawValue, using: keyDerivator)
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

extension ExtendedKey {
    /**
     * Creates an extended (child) key from this parent key.
     *
     * - parameter childKey     : The type of derivation used to extend the parent.
     * - parameter index        : The index the the derived key will use.
     * - parameter keyDerivator : The type which implements certain key derivation algorithms.
     */
    private func extended(_ childKey: ChildKeyDerivator, atIndex index: UInt32, using keyDerivator: KeyDerivator.Type) throws -> ExtendedKey {
        try childKey.derived(atIndex: index, fromParentKey: self, using: keyDerivator).get()
    }

    /**
     * An enumuration describing a proposed derivation of an extended (child)
     * key, and how it should be derived.
     *
     * In the case of a `private` child key derivation, the resuling key can be
     * either _hardened_ or _not hardened_).
     */
    public enum ChildKeyDerivator {
        case privateKey(hardened: Bool)
        case publicKey
        
        /// Indicates that the extended (child) key being derived _is hardened_.
        ///
        /// There are two posible types of **BIP32** derivation, hardened or non-hardened.
        /// In standard **BIP32** path notation, hardened derivation at a particular
        /// level is indicated by an apostrophe.
        ///
        /// https://wiki.trezor.io/Hardened_and_non-hardened_derivation
        private var isHardened: Bool {
            switch self {
            case .privateKey(true) :return true
            default                :return false
            }
        }
        
        /// Indicates that the extended (child) key being derived is either a
        /// _public_ key, or a _private_ key.
        ///
        /// - note: A _public_ parent key cannot derive a _private_ extended key.
        private var sector: Sector {
            switch self {
            case .privateKey :return .private
            case .publicKey  :return .public
            }
        }
        
        /**
         * Determines is a proposed `ChildKeyDerivator` is valid for the given
         * `parent` key.
         *
         * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
         *
         * - parameter parent: The source key for the extended key this derivation is proposing.
         * - returns: If the `true`, the child derivation can proceed.
         */
        private func canExtend(parentKey parent: ExtendedKey) -> Bool {
            switch (from: parent.network.sector, to: sector) {
            case /* #1 */ (.private, .private) :return true
            case /* #2 */ (.private, .public)  :return true
            case /* #3 */ (.public,  .public)  :return true
            case /* #4 */ (.public,  .private) :return false
            }
        }

        /**
         * - parameter index       :
         * - parameter parent      :
         * - parameter keyDerivator:
         *
         * - returns: A `Result` with the new instantiated extended (child) key.
         */
        fileprivate func derived(atIndex index: UInt32, fromParentKey parent: ExtendedKey, using keyDerivator: KeyDerivator.Type) -> Result<ExtendedKey, ExtendedKey.Error> {
            guard canExtend(parentKey: parent) else {
                return .failure(.childKeyDerivatorError(.invalidDerivation(to: self, from: parent)))
            }
            
            do {
                // Attempt to generate the next `depth`.
                let nextDepth = try parent.depth.nextDepth().wrappedValue
                
                // Create the `childIndex`; 'wrappedValue' adjusts depending on 'isHardened'
                let childIndex: KeyIndex = isHardened ? .hardened(index) : .normal(index)
                
                // TODO: 'Public' -> 'public': currently not working...
                let childKeyData: (key: Data, chainCode: Data) = try {
                    switch sector {
                    case .public :
                        return try self.publicKey(forChildIndex: childIndex, fromParentKey: parent, using: keyDerivator)
                    case .private:
                        return try self.privateKey(forChildIndex: childIndex, fromParentKey: parent, using: keyDerivator)
                    }
                }()

                // Generate the child's `fingerprint` from the `parent`.
                let fingerprint: UInt32 = UInt32(data: try keyDerivator.hash160(data: try parent.publicKey().key).get()[...3])!

                // Instantiate the `childKey`.
                let childKey = try ExtendedKey(
                    pathURL     :parent.pathURL.appendingPathComponent(childIndex.description),
                    depth       :nextDepth,
                    version     :parent.network.switched(to: sector),
                    fingerprint :fingerprint,
                    index       :childIndex,
                    chainCode   :childKeyData.chainCode,
                    key         :childKeyData.key
                )
                
                // Return
                return .success(childKey)
            }
            catch let error as Error {
                guard case .invalidIntermediaryKey = error, index < .max else {
                    return .failure(.childKeyDerivatorError(error))
                }
                return derived(atIndex: index + 1, fromParentKey: parent, using: keyDerivator)
            }
            catch let error as KeyDerivatorError {
                return .failure(.childKeyDerivatorError(.keyDerivatorError(error)))
            }
            catch let error as ExtendedKey.Error {
                return .failure(error)
            }
            catch {
                return .failure(.childKeyDerivatorError(.unknown(error)))
            }
        }
        
        /**
         * - parameter index       :
         * - parameter parent      :
         * - parameter keyDerivator:
         *
         * - returns: This function returns the child's `key` and `chainCode`.
         */
        private func privateKey(forChildIndex index: KeyIndex, fromParentKey parent: ExtendedKey, using keyDerivator: KeyDerivator.Type) throws -> (key: Data, chainCode: Data) {
            let chainKeyData = isHardened ? parent.key : try parent.publicKey().key
            
            let intermediateKey = try keyDerivator
                .hmac(SHA512.self, key: parent.chainCode, data: chainKeyData + index.bytes)
                .mapError { ChildKeyDerivator.Error.keyDerivatorError($0) }
                .mapError { ExtendedKey.Error.childKeyDerivatorError($0) }
                .map { (key: $0[..<32], chainCode: $0[32...]) }
                .get()
            
            let parentKeyNum = BigUInt(parent.key)
            let intermKeyNum = BigUInt(intermediateKey.key)
            
            guard intermKeyNum < .CurveOrder, intermKeyNum != 0 else {
                throw Error.invalidIntermediaryKey(intermKeyNum)
            }
            
            switch parent.network.sector {
            case .private:
                let childKey: Data = {
                    var childKeyNum = parentKeyNum
                    childKeyNum += intermKeyNum
                    childKeyNum %= .CurveOrder
                    return childKeyNum.serialize()
                }()
                
                return (key: childKey, chainCode: intermediateKey.chainCode)
                
            case .public:
                let intermPubKey = try keyDerivator.secp256k_1(data: intermediateKey.key, compressed: true).get()
                let childKey = BigUInt(intermPubKey) + parentKeyNum
                
                return (key: childKey.serialize(), chainCode: intermediateKey.chainCode)
            }
        }
        
        private func publicKey(forChildIndex index: KeyIndex, fromParentKey parent: ExtendedKey, using keyDerivator: KeyDerivator.Type) throws -> (key: Data, chainCode: Data) {
            let parentPubKey = try parent.publicKey().key
            
            let _ = try keyDerivator
                .hmac(SHA512.self, key: parent.chainCode, data: parentPubKey + index.bytes)
                .mapError { ChildKeyDerivator.Error.keyDerivatorError($0) }
                .mapError { ExtendedKey.Error.childKeyDerivatorError($0) }
                .map { (left: $0[..<32], right: $0[32...]) }
                .get()
            
            // https://en.bitcoin.it/wiki/Secp256k1
            // https://github.com/MetacoSA/NBitcoin/blob/master/NBitcoin/PubKey.cs#L601
            // (G * key.left) + pubKey
            
            fatalError("Can't figure this out")
        }
    }
}

/**
 * `ExtendedKey` errors which may occur.
 */
extension ExtendedKey {
    public enum Error: Swift.Error {
        /// Convert a `ChildKeyDerivator.Error` to `ExtendedKey.Error`.
        case childKeyDerivatorError(ChildKeyDerivator.Error)
        
        /// Catches failures on extended key created with malformed data.
        case invalidSerializedKey(Data)
    }
}

/**
 *
 */
extension ExtendedKey.ChildKeyDerivator {
    public enum Error: Swift.Error {
        /// Thrown when a _child_ derivation from a _parent_ is not feasible.
        /// - note: This error will be thrown if `from` is _public_, and `to` is _private_.
        case invalidDerivation(to: ExtendedKey.ChildKeyDerivator, from: ExtendedKey)
        
        /// Catches an error caused when a child's extended key (when interpreted
        /// as a 256-bit number) is found to be outside of the acceptable range.
        ///
        /// Both derived public or private keys rely on treating the left
        /// 32-byte sequence calculated above (Il) as a 256-bit integer that must be
        /// within the valid range for a secp256k1 private key.  There is a small
        /// chance (< 1 in 2^127) this condition will not hold, and in that case,
        /// a child extended key can't be created for this index and the caller
        /// should simply increment to the next index.
        ///
        /// - note: This error is caught internally.
        case invalidIntermediaryKey(BigUInt)
        
        /// Catches and converts errors thrown from `KeyDerivator` routines.
        case keyDerivatorError(KeyDerivatorError)
        
        /// Catches an out-of-bounds error when determing the next `depth` value.
        case depthError(KeyDepth.Error)
        
        /// Catches all over errors. Good luck! ¯\_(ツ)_/¯
        case unknown(Swift.Error)
    }
    
}

fileprivate extension BigUInt {
    /// Modulo constant (referred to a `n` in **BIP32** spec) used for
    /// calculating extended private keys.
    static let CurveOrder: BigUInt = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
}

