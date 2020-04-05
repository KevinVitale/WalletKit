import Foundation

public extension RIPEMD160 {

    static func hash(data message: Data) -> Data {
        var md = RIPEMD160()
        md.update(data: message)
        return md.finalize()
    }

    static func hash(message: String) -> Data {
        return RIPEMD160.hash(data: message.data(using: .utf8)!)
    }
}
