import Foundation

@propertyWrapper
public enum Network: RawRepresentable, Codable, CustomStringConvertible {
    private static let MainnetPublic   : UInt32 = 0x0488B21E
    private static let MainnetPrivate  : UInt32 = 0x0488ADE4
    private static let TestnetPublic   : UInt32 = 0x043587CF
    private static let TestnetPrivate  : UInt32 = 0x04358394
    
    public init?(rawValue: UInt32) {
        switch rawValue {
        case Network.MainnetPrivate :self = .mainnet(.private)
        case Network.MainnetPublic  :self = .mainnet(.public)
        case Network.TestnetPrivate :self = .testnet(.private)
        case Network.TestnetPublic  :self = .testnet(.public)
        default         :return nil
        }
    }
    
    public init?<D: DataProtocol>(data: D) {
        guard let rawValue = RawValue(data: data), let network = Network(rawValue: rawValue) else {
            return nil
        }
        self = network
    }
    
    case mainnet(Sector)
    case testnet(Sector)

    public var sector: Sector {
        switch self {
        case .mainnet(let sector): return sector
        case .testnet(let sector): return sector
        }
    }
    
    public var wrappedValue: RawValue {
        rawValue
    }
    
    public var rawValue: UInt32 {
        switch self {
        case .mainnet(let sector):
            switch sector {
            case .private : return Network.MainnetPrivate
            case .public  : return Network.MainnetPublic
            }
        case .testnet(let sector):
            switch sector {
            case .private : return Network.TestnetPrivate
            case .public  : return Network.TestnetPublic
            }
        }
    }
    
    public var description: String {
        switch self.rawValue {
        case Network.MainnetPublic  : return "Mainnet -- Public\t(hex: \(hexString))"
        case Network.MainnetPrivate : return "Mainnet -- Private\t(hex: \(hexString))"
        case Network.TestnetPublic  : return "Testnet -- Public\t(hex: \(hexString))"
        case Network.TestnetPrivate : return "Testnet -- Private\t(hex: \(hexString))"
        default: return "ERROR: Unknown 'Network'"
        }
    }
    
    public var hexString: String {
        "0x" + String(rawValue, radix: 16, uppercase: true)
    }
    
    public var bytes: [UInt8] {
        rawValue.bytes
    }
}

extension Network {
    func switched(to sector: Sector) -> Network {
        switch self {
        case .mainnet: return .mainnet(sector)
        case .testnet: return .testnet(sector)
        }
    }
}

public enum Sector {
    case `private`
    case `public`
}
