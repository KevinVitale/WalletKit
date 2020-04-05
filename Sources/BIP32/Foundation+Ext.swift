import CryptoCore

public extension DataProtocol {
    var keccak256: Data {
        var input  = map { $0 }
        var result = [UInt8](repeating: 0, count: 32)
        keccak_256(&result, 32, &input, input.count)
        return Data(result)
    }
}

extension FixedWidthInteger {
    init?<D: DataProtocol>(data: D) {
        guard let value = Self(data.hexString, radix: 16) else {
            return nil
        }
        self = value
    }
    
    public var bytes: [UInt8] {
        withUnsafeBytes(of: self.byteSwapped, Array.init)
    }
}
