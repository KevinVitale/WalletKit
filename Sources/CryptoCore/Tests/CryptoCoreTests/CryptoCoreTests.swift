import XCTest
import CryptoCore

final class CryptoCoreTests: XCTestCase {
  func testCryptoCore() throws {
    print(try! Data(hexString: "30").hexString)
    print("Hello")
  }
}

