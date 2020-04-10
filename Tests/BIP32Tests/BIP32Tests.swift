import XCTHelpers

final class BIP32Tests: XCTestCase {
    func testRootKeyPublicKey() throws {
        let seedsAndAccounts = [
            "000102030405060708090a0b0c0d0e0f":
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542":
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
           
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be":
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        ]
        
        for (_, (seed, account)) in seedsAndAccounts.enumerated() {
            let publicKey = try ExtendedKey(seedHexString: seed, version: .mainnet(.public))
            XCTAssertTrue(publicKey == account)
            print("Root Key:", publicKey)
            print("Network:", publicKey.network)
            print("Depth:", publicKey.depth)
            print("Fingerprint:", publicKey.fingerprint.bytes)
            print("Index:", publicKey.index)
            print("Chain Code:", publicKey.chainCode.hexString, "\(publicKey.chainCode)")
            print("")
            
        }
    }

    func testRootKeyPrivateKey() throws {
        let seedsAndAccounts = [
            "000102030405060708090a0b0c0d0e0f":
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542":
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
            
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be":
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        ]
        
        for (_, (seed, account)) in seedsAndAccounts.enumerated() {
            let rootKey = try ExtendedKey(seedHexString: seed, version: .mainnet(.private))
            XCTAssertTrue(rootKey == account)
            print("Root Key:", rootKey)
            print("Public Key:", try rootKey.publicKey())
            print("Network:", rootKey.network)
            print("Depth:", rootKey.depth)
            print("Fingerprint:", rootKey.fingerprint.bytes)
            print("Index:", rootKey.index)
            print("Chain Code:", rootKey.chainCode.hexString, "\(rootKey.chainCode)")
            print("")
        }
    }

    func testChildKeyDerivatorFromPrivateToPrivateNotHardenedSucceeds() throws {
        let rootKey  = try ExtendedKey(
            seedHexString: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            version      : .mainnet(.private)
        )
        var childKey = try rootKey.privateKey(atIndex: .normal(0))
        var childPublicKey = try childKey.publicKey()

        XCTAssertTrue(childKey == "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        XCTAssertTrue(childPublicKey == "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
        
        childKey = try childKey.privateKey(atIndex: .normal(0))
        childPublicKey = try childKey.publicKey()
        
        XCTAssertTrue(childKey == "xprv9wSp6B7UBdyZR3rpPXH95XSurvExuGcic5wVTcZg1a2kYFSX1scgji5ofnjQ6HRZFkZQ1fyKxL8JpjvLpMhw78UdTeGRiKwmTbX3WNcnaV8")
        XCTAssertTrue(childPublicKey == "xpub6ASAVgeN21XrdXwHVYp9SfPeQx5TJjLZyJs6FzyHZuZjR3mfZQvwHWQHX3EHtVDzUUTuke7H6Z9sbmxzoh4bkFnrxG6JQGEuQ1WfX1Bfh3Z")
    }
    
    func testChildKeyDerivatorFromPrivateTestnetToPrivateNotHardenedSucceeds() throws {
        let rootKey  = try ExtendedKey(
            seedHexString: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            version      : .testnet(.private)
        )
        let childKey = try rootKey.privateKey(atIndex: .normal(0))
        let childPublicKey = try childKey.publicKey()

        XCTAssertTrue(rootKey == "tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J")
        XCTAssertTrue(childKey == "tprv8cuCuYDY1CfruLwNg8JnjBvbrxgZnefmAF5bKScg3rAKSY7upRNYxTd86hhCwatUey2NHkYq4YFWkDiKpdcEwok7UV9kvoFXWAhH3Cx1KDa")
        XCTAssertTrue(childPublicKey == "tpubD9bF3xFn9aMXnoyAZmyP8baiRzCVwyrfjYgNbxeyU7xiH2NgSpC98xEzGr97dsXGfd1jsWVmrFL3hUat8hFwmq6bpFKwZyUVCcgw6eBEwVB")

        print(childKey, "\n\(childPublicKey)")
    }
    
    func testChildKeyDerivatorFromPrivateToPrivateHardenedSucceeds() throws {
        let rootKey  = try ExtendedKey(
            seedHexString: "000102030405060708090a0b0c0d0e0f",
            version      : .mainnet(.private)
        )
        let childKey = try rootKey.privateKey(atIndex: .hardened(0))
        let childPublicKey = try childKey.publicKey()
        
        XCTAssertTrue(childKey == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        XCTAssertTrue(childPublicKey == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
        
        print(childKey, "\n\(childPublicKey)")
    }
    
    func testChildKeyDerivatorFromPrivateToPrivateWithLeadingZeroesHardenedSucceeds() throws {
        let rootKey  = try ExtendedKey(
            seedHexString: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            version      : .mainnet(.private)
        )
        let childKey = try rootKey.privateKey(atIndex: .hardened(0))
        let childPublicKey = try childKey.publicKey()
        
        XCTAssertTrue(childKey == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        XCTAssertTrue(childPublicKey == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")
        
        print(childKey, "\n\(childPublicKey)")
    }
    
    func testPublicToPublicKeyDerivationFails() throws {
        let publicKey = try ExtendedKey(
            seedHexString: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            version      : .mainnet(.public))
        XCTAssertThrowsError(try publicKey.publicKey(atIndex: .normal(0)))
    }
    
    func testChildKeyDerivatorFromPrivateToPrivatePublicHardenedSucceeds() throws {
        let rootKey  = try ExtendedKey(
            seedHexString: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            version      : .mainnet(.private)
        )
        let childKey = try rootKey
            .privateKey(atIndex: .normal(0))
            .privateKey(atIndex: .hardened(2147483647))

        XCTAssertTrue(childKey == "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        
        print(childKey)
    }
    
    func testChildKeyDerivatorFromPublicToPrivateFails() throws {
        let rootKey = try ExtendedKey(
            seedHexString: "000102030405060708090a0b0c0d0e0f",
            version      : .mainnet(.public)
        )
        XCTAssertThrowsError(try rootKey.privateKey(atIndex: .normal(0)))
    }

    func testExtendedKeyAtMaxDepthFails() throws {
        XCTAssertThrowsError(try KeyDepth(wrappedValue: .max).nextDepth())
    }
}
