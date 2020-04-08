import Foundation

@propertyWrapper
public struct KeyIndex: Equatable, CustomStringConvertible {
    public enum Error: Swift.Error {
        case invalidIndex(UInt32)
    }

    public init(wrappedValue index: UInt32, hardened: Bool = false) {
        self._hardened = hardened
        self._index    = index
    }

    public var wrappedValue: UInt32 {
        get { _hardened ? 0x80000000 | _index : _index }
        set { _index = newValue }
    }
    
    private var _index    :UInt32
    private var _hardened :Bool
    
    public var isHardened: Bool {
        _hardened
    }
    
    public var bytes: [UInt8] {
        wrappedValue.bytes
    }
    
    public var description: String {
        "/\(_index)" + (_hardened ? "'" : "")
    }

    public static let zero = KeyIndex(wrappedValue: .zero)
}
