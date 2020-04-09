import Foundation

@propertyWrapper
public struct KeyIndex: Equatable, CustomStringConvertible {
    public enum Error: Swift.Error {
        case invalidIndex(RawValue)
    }

    public init(wrappedValue index: UInt32, hardened: Bool) {
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
}

extension KeyIndex {
    static let masterIndex = KeyIndex(rawValue: 0)
}

extension KeyIndex {
    public static func hardened<Value: BinaryInteger>(_ wrappedValue: Value) -> KeyIndex {
        KeyIndex(wrappedValue: UInt32(wrappedValue), hardened: true)
    }
    
    public static func normal<Value: BinaryInteger>(_ wrappedValue: Value) -> KeyIndex {
        KeyIndex(wrappedValue: UInt32(wrappedValue), hardened: false)
    }
}

extension KeyIndex: RawRepresentable {
    public init(rawValue: UInt32) {
        switch rawValue {
        case 0..<0x80000000:
            self = KeyIndex(wrappedValue: rawValue, hardened: false)
        default:
            self = KeyIndex(wrappedValue: rawValue - 0x80000000, hardened: true)
        }
    }
    
    public var rawValue: UInt32 { _index }
}

extension KeyIndex {
    public func index(after keyIndex: KeyIndex) -> KeyIndex {
        KeyIndex(wrappedValue: keyIndex._index.advanced(by: 1), hardened: isHardened)
    }
}

extension KeyIndex: Strideable {
    public typealias Stride = Int
    
    public func distance(to other: KeyIndex) -> Int {
        _index.distance(to: other._index)
    }
    
    public func advanced(by n: Int) -> KeyIndex {
        KeyIndex(wrappedValue: _index.advanced(by: n), hardened: isHardened)
    }
}
