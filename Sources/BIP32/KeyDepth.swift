@propertyWrapper
/**
 * A wrapper around a `UInt8` number (between 0...255).
 */
public struct KeyDepth {
    public enum Error: Swift.Error {
        /// Thrown when `nextDepth` is advanced past `UInt8.max`.
        case invalidDepth(UInt)
    }
    
    /**
     * - parameter depth:
     */
    public init(wrappedValue depth: UInt8) {
        self.wrappedValue = depth
    }
    
    /// The underlying `depth` value.
    public var wrappedValue: UInt8
    
    /**
     * Increments this `KeyDepth` by one.
     *
     * - warning: If the resulting value is equal to, or greater, than what an
     *            unsigned 8-bit number can how (255), then this function throws
     *            an `invalidDepth` error.
     */
    public func nextDepth() throws -> KeyDepth {
        guard wrappedValue < .max else {
            throw Error.invalidDepth(UInt(wrappedValue).advanced(by: 1))
        }
        return KeyDepth(wrappedValue: wrappedValue.advanced(by: 1))
    }
}
