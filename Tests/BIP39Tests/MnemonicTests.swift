import XCTHelpers

final class MnemonicTests: XCTestCase {
    func testVectorFixtures() throws {
        let tests = try XCTFixture<BIP39TestVectors>.loadTests()

        for (idx, vector) in tests.enumerated() {
            let mnemonic = try Mnemonic(entropy: vector)
            let seedDflt = try mnemonic.seed(passphrase: "TREZOR").map(String.init(hexEncoding:)).get()
            let seedBSSL = try mnemonic.seed(passphrase: "TREZOR", derivator: BoringSSLSeedDerivator.self).map(String.init(hexEncoding:)).get()

            XCTAssertEqual(mnemonic, try Mnemonic(seedPhrase: vector.words.joined(separator: " "))) // Test `Equatable` conformance
            XCTAssertEqual(seedDflt, vector.binarySeed)             // Test `seed` generation ("platform default")
            XCTAssertEqual(seedBSSL, vector.binarySeed)             // Test `seed` generation ("BoringSSL")
            
            print("|\(idx): \(mnemonic)")
            print("|\(idx): \(seedDflt)")
            if idx != tests.endIndex - 1 { print("|") }
        }
    }

    func testMnemonicCreateWithBadWords() throws {
        //----------------------------------------------------------------------
        // Do not create a `Mnemonic` like this. **TESTING ONLY**
        //----------------------------------------------------------------------
        let testWords = try WordList.english.randomWords(withEntropy: 128)
        XCTAssertThrowsError(try Mnemonic(seedPhrase: Array(testWords[0..<10]).joined(separator: " ")))
    }
    
    func testMnemonicWithStrength() throws {
        let wordCounts     = [ 12, 15, 18, 21, 24 ]
        let strengthValues = [ 128, 160, 192, 224, 256 ]
        
        for (strength, wordCount) in zip(strengthValues, wordCounts) {
            print("Mnemonic with \(wordCount) words; \(strength)")
            
            let mnemonic = try Mnemonic(entropy: strength)
            
            XCTAssertEqual(mnemonic.words.count, wordCount)
        }
    }
}
