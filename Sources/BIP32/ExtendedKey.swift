import CryptoCore
import BigInt

@propertyWrapper
public struct ExtendedKey {
    public enum Error: Swift.Error {
        case childKeyDerivatorError(ChildKeyDerivator.Error)
        case initalizationFailed(withIndex: KeyIndex)
        case invalidSerializedKey(Data)
        case rootKeyInitializationAsPublicKey
        case unknown
    }
    
    init(masterKey: (key: Data, chainCode: Data), version network: Network) throws {
        guard case .private = network.sector else {
            throw Error.rootKeyInitializationAsPublicKey
        }
        
        self = try .init(
            depth       :0,
            version     :network,
            fingerprint :0,
            index       :.zero,
            chainCode   :masterKey.chainCode,
            key         :masterKey.key
        )
    }
    
    init(depth: UInt8, version network: Network, fingerprint: UInt32, index: KeyIndex, chainCode: Data, key: Data, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws {
        let serializedKey: Data = try {
            var data = Data(capacity: 78)
            
            data += network.bytes
            data += depth.bytes
            data += fingerprint.bytes
            data += index.bytes
            data += chainCode
            data += network.sector == .private ? [0x00] + key : try ExtendedKey.computePublicKey(forData: key, using: keyDerivator)

            return data
        }()
        
        self = try .init(serializedKey: serializedKey)
    }
    
    public init(serializedKey: Data) throws {
        guard serializedKey.count == 78 else {
            throw Error.invalidSerializedKey(serializedKey)
        }

        self.wrappedValue = serializedKey
        self._description = {
            func sha256(from data: Data) -> Data {
                var sha256 = SHA256()
                sha256.update(data: data)
                return Data(sha256.finalize())
            }
            
            let checksum = sha256(from: sha256(from: serializedKey))[..<4]
            return Base58.encode(serializedKey + checksum)
        }()
    }
    
    private let _description :String
    
    public private(set) var wrappedValue: Data
}

extension ExtendedKey {
    fileprivate static func computePublicKey(forData data: Data, using keyDerivator: KeyDerivator.Type) throws -> Data {
        try keyDerivator.secp256k_1(data: data, compressed: true).get()
    }

    public func publicKey() throws -> ExtendedKey {
        guard case .private = network.sector else {
            return self
        }
        
        return try ExtendedKey(
            depth       : depth.wrappedValue,
            version     : network.switched(to: .public),
            fingerprint : fingerprint,
            index       : index,
            chainCode   : chainCode,
            key         : key.dropFirst()
        )
    }
    
    public func address(using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> Data {
        throw Error.unknown
    }
}

extension ExtendedKey {
    public var network: Network {
        Network(data: wrappedValue[...3])!
    }
    
    public var depth: KeyDepth {
        KeyDepth(wrappedValue: wrappedValue[4])
    }
    
    public var fingerprint: UInt32 {
        UInt32(data: wrappedValue[5...8])!
    }
    
    public var index: KeyIndex {
        KeyIndex(wrappedValue: UInt32(data: wrappedValue[9...12])!)
    }
    
    public var chainCode: Data {
        wrappedValue[13...44]
    }
    
    public var key: Data {
        wrappedValue[45...]
    }
}

extension ExtendedKey: CustomStringConvertible {
    public var description: String {
        _description
    }
}

extension ExtendedKey: Equatable {
    public static func ==(lhs: ExtendedKey, rhs: ExtendedKey) -> Bool {
        lhs.wrappedValue == rhs.wrappedValue
    }
    
    public static func ==(lhs: ExtendedKey, rhs: String) -> Bool {
        lhs.description == rhs
    }
}

extension ExtendedKey {
    public func callAsFunction(extended childKey: ChildKeyDerivator, atIndex index: UInt32, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> ExtendedKey {
        try self.extended(childKey, atIndex: index, using: keyDerivator)
    }

    func extended(_ childKey: ChildKeyDerivator, atIndex index: UInt32, using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> ExtendedKey {
        try childKey.derived(atIndex: index, fromParentKey: self, using: keyDerivator).get()
    }
    
    public enum ChildKeyDerivator {
        public enum Error: Swift.Error {
            case invalidDerivation(to: ChildKeyDerivator, from: ExtendedKey)
            case invalidIntermediaryKey(BigUInt)
            case keyDerivatorError(KeyDerivatorError)
            case depthError(KeyDepth.Error)
            case unknown
        }
        
        case privateKey(hardened: Bool)
        case publicKey
        
        private var isHardened: Bool {
            switch self {
            case .privateKey(true) :return true
            default                :return false
            }
        }
        
        private var sector: Sector {
            switch self {
            case .privateKey :return .private
            case .publicKey  :return .public
            }
        }
        
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
        private func canExtend(parentKey parent: ExtendedKey) -> Bool {
            switch (from: parent.network.sector, to: sector) {
            case /* #1 */ (.private, .private) :return true
            case /* #2 */ (.private, .public)  :return true
            case /* #3 */ (.public,  .public)  :return true
            case /* #4 */ (.public,  .private) :return false
            }
        }

        private func childKeyData(forChildIndex index: KeyIndex, fromParentKey parent: ExtendedKey, using keyDerivator: KeyDerivator.Type) throws -> (key: Data, chainCode: Data) {
            print("Deriving \(sector) child (from (\(parent.network.sector) parent), at index: \(index); \(index.bytes)")
            //------------------------------------------------------------------
            /// `index` could be either _hardened_, or _not hardened_.
            /// `parent.key` is serialized into the correct format  as part of _initialization_.
            //------------------------------------------------------------------
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
        
        func derived(atIndex index: UInt32, fromParentKey parent: ExtendedKey, using keyDerivator: KeyDerivator.Type) -> Result<ExtendedKey, ExtendedKey.Error> {
            guard canExtend(parentKey: parent) else {
                return .failure(.childKeyDerivatorError(.invalidDerivation(to: self, from: parent)))
            }
            
            do {
                // Attempt to generate the next `depth`.
                let nextDepth    = try parent.depth.nextDepth().wrappedValue
                
                // Create the `childIndex`, and calculate key date accordingly.
                let childIndex   = KeyIndex(wrappedValue: index, hardened: self.isHardened)
                let childKeyData = try self.childKeyData(forChildIndex: childIndex, fromParentKey: parent, using: keyDerivator)

                // Generate the child's `fingerprint` from the `parent`.
                let fingerprint: UInt32 = UInt32(data: try keyDerivator.hash160(data: try parent.publicKey().key).get()[...3])!

                // Instantiate the `childKey`.
                let childKey = try ExtendedKey(
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
                return .failure(.childKeyDerivatorError(.unknown))
            }
        }
    }
}

fileprivate extension BigUInt {
    static let CurveOrder: BigUInt = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
}

