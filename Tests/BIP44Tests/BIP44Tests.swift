import XCTHelpers

final class BIP44Tests: XCTestCase {
    
    func testMultiAccountHierarchyFromMnemonic() throws {
        let seedPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let mnemonic   = try Mnemonic(seedPhrase: seedPhrase)
        let wallet     = try mnemonic.wallet(coinType: BTC.self, passphrase: "TREZOR").get()
        let account    = try wallet.account(atIndex: 0)
        
        account[.hardened(0..<10)].forEach {
            print($0.publicKey, $0.pathURL, $0.privateKey)
        }
    }
    
    func testMultiAccountHierarchyFromSeedHexString() throws {
        let seed     = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        let wallet   = try Wallet<BTC>(seedHexString: seed)
        let account  = try wallet.account(atIndex: 0)
        
        account[.hardened(0..<10)].forEach {
            print($0.publicKey, $0.pathURL, $0.privateKey)
        }
    }
}
