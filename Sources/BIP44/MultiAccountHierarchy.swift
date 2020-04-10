import BIP32

public struct MultiAccountHierarchy: CustomStringConvertible {
    public init(purpose: UInt32, coinType: UInt32, account: UInt32, change: UInt) {
        self._purpose  = KeyIndex(wrappedValue: purpose, hardened: true)
        self._coinType = KeyIndex(wrappedValue: coinType, hardened: true)
        self._account  = KeyIndex(wrappedValue: account, hardened: true)
        self.change    = change
    }
    
    @KeyIndex
    public var purpose  : UInt32 
    
    @KeyIndex 
    public var coinType : UInt32
    
    @KeyIndex
    public var account  : UInt32
    
    public let change   : UInt

    public var description: String {
        "m\(_purpose.description)\(_coinType.description)\(_account.description)/\(change)"
    }
}

extension MultiAccountHierarchy: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        fatalError("Not yet implemented")
    }
}
