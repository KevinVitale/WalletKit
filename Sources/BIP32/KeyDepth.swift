@propertyWrapper
public struct KeyDepth {
    public enum Error: Swift.Error {
        case invalidDepth(UInt)
    }
    
    public init(wrappedValue depth: UInt8) {
        self.wrappedValue = depth
    }
    
    public var wrappedValue: UInt8
    
    public func nextDepth() throws -> KeyDepth {
        guard wrappedValue < .max else {
            throw Error.invalidDepth(UInt(wrappedValue).advanced(by: 1))
        }
        return KeyDepth(wrappedValue: wrappedValue.advanced(by: 1))
    }
}
