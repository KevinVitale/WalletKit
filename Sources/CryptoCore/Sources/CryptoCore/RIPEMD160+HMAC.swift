import Foundation

public extension RIPEMD160 {

    static func hmac(key: Data, message: Data) -> Data {

        var key = key
        key.count = 64 // Truncate to 64 bytes or fill-up with zeros.

        let outerKeyPad = Data(key.map { $0 ^ 0x5c })
        let innerKeyPad = Data(key.map { $0 ^ 0x36 })

        var innerMd = RIPEMD160()
        innerMd.update(data: innerKeyPad)
        innerMd.update(data: message)

        var outerMd = RIPEMD160()
        outerMd.update(data: outerKeyPad)
        outerMd.update(data: innerMd.finalize())

        return outerMd.finalize()
    }

    static func hmac(key: Data, message: String) -> Data {
        return RIPEMD160.hmac(key: key, message: message.data(using: .utf8)!)
    }

    static func hmac(key: String, message: String) -> Data {
        return RIPEMD160.hmac(key: key.data(using: .utf8)!, message: message)
    }
}