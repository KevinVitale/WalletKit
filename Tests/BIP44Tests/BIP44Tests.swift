import XCTHelpers

final class BIP44Tests: XCTestCase {
    
    func testMultiAccountHierarchyFromMnemonic() throws {
        let seedPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let wallet     = try Mnemonic(seedPhrase: seedPhrase).createWallet(passphrase: "TREZOR")
        let account    = try wallet.account(coinType: .ETH, atIndex: 0)
        
        account[.hardened(0..<10)].forEach {
            print($0.address, $0.pathURL)
        }
    }
    
    func testMultiAccountHierarchyFromSeedHexString() throws {
        let seed     = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        let wallet   = Wallet(withRootKey: try ExtendedKey(seedHexString: seed, version: .mainnet(.private)))
        let account  = try wallet.account(coinType: .ETH, atIndex: 0)
        
        account[.hardened(0..<10)].forEach {
            print($0.address, $0.pathURL)
        }
    }
    
    func testEthAccounts() throws {
        let seedPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let addressesAndPrivateKeys: [(String, String)] = [
            ( "0x9858EfFD232B4033E47d90003D41EC34EcaEda94","0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727" ),
            ( "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0","0x9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6" ),
            ( "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A","0x5b824bd1104617939cd07c117ddc4301eb5beeca0904f964158963d69ab9d831" ),
            ( "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E","0x9ffce93c14680776a0c319c76b4c25e7ad03bd780bf47f27ae9153324dcac585" ),
            ( "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA","0xbd443149113127d73c350d0baeceedd2c83be3f10e3d57613a730649ddfaf0c0" ),
            ( "0xA40cFBFc8534FFC84E20a7d8bBC3729B26a35F6f","0x5a8787e6b7e11a74a22ee97b8164c7d69cd5668c6065bbfbc87e6a34a24b135c" ),
            ( "0xB191a13bfE648B61002F2e2135867015B71816a6","0x56e506258e5b0e3b6023b17941d84f8a13d655c525419b9ff0a52999a2c687a3" ),
            ( "0x593814d3309e2dF31D112824F0bb5aa7Cb0D7d47","0xdfb0930bcb8f6ca83296c1870e941998c641d3d0d413013c890b8b255dd537b5" ),
            ( "0xB14c391e2bf19E5a26941617ab546FA620A4f163","0x66014718190fedba55dc3f4709f6b5b34b9b1feebb110e7b87391054cbbffdd2" ),
            ( "0x4C1C56443AbFe6dD33de31dAaF0a6E929DBc4971","0x22fb8f2fe3b2dbf632bc5eb450a96ec56185733234f17e49c2483bb337ebf145" ),
        ]

        let mnemonic   = try Mnemonic(seedPhrase: seedPhrase)
        let wallet     = try mnemonic.createWallet()
        let account    = try wallet.account(coinType: .ETH, atIndex: 0)
        
        print("\(account.pathURL)/{idx}")
        
        zip(account[.normal(0..<10)], addressesAndPrivateKeys.enumerated()).forEach { (account, itr) in
            let address    = account.address
            let privateKey = "0x" + account.privateKey.key.dropFirst().hexString
            print("[idx: \(itr.offset)]", address, privateKey)
            
            XCTAssertEqual(address.lowercased(), itr.element.0.lowercased())
            XCTAssertEqual(privateKey, itr.element.1)
        }
    }

    func testNewHDWallet() throws {
        let mnemonic = try Mnemonic()
        print(mnemonic.phrase)

        let accounts = try mnemonic.createWallet().account(coinType: .ETH, atIndex: 0)
        accounts[.normal(0..<10)].enumerated().forEach { (index, account) in
            let address = account.address
            let privateKey = "0x" + account.privateKey.key.dropFirst().hexString

            print("[idx: \(index)]", address, privateKey)

        }
    }

    func testSeedPhrase() throws {
        let seedPhrases = [
            try WordList.english.randomWords(withEntropy: Int.strongest).joined(separator: " "),
            try WordList.japanese.randomWords(withEntropy: Int.strongest).joined(separator: " "),
            try WordList.chinese.randomWords(withEntropy: Int.strongest).joined(separator: " ")
        ]

        seedPhrases.forEach { print($0) }

        let accounts = try seedPhrases
            .map(Mnemonic.init(seedPhrase:))
            .map({ try $0.createWallet() })
            .map({ try $0.account(coinType: .ETH, atIndex: 0) })
            .map({ $0[.normal(0..<2)] })
            .flatMap({
                $0.enumerated().map { (index, account) -> (address: String, privateKey: String) in
                    let address = account.address
                    let privateKey = "0x" + account.privateKey.key.dropFirst().hexString
                    return (address, privateKey)
                }
            })
        accounts.forEach {
            print($0)
        }
    }
}
