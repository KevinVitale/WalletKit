import XCTHelpers

final class MnemonicTests: XCTestCase {
    func testVectorFixtures() throws {
        let fixture = try XCTFixture<XCTTestJSON>(fileNamed: "TestVectors.json")
        let tests   = try fixture.loadTests()
        
        for (idx, vector) in tests.enumerated() {
            let mnemonic = try Mnemonic(entropy: vector.inputEntropy)
            let seedDflt = try mnemonic.seed(passphrase: "TREZOR").map(String.init(hexEncoding:)).get()
            let seedBSSL = try mnemonic.seed(passphrase: "TREZOR", derivator: BoringSSLSeedDerivator.self).map(String.init(hexEncoding:)).get()

            XCTAssertEqual(mnemonic, Mnemonic(words: vector.words)) // Test `Equatable` conformance
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
        let testWords = try WordList.english.randomWords(withEntropy: Mnemonic.Strength.weakest)
        let mnemonic  = Mnemonic(words: Array(testWords[0..<10]))
        XCTAssertNil(mnemonic)
    }
    
    func testMnemonicWithStrength() throws {
        let wordCounts     = [ 12, 15, 18, 21, 24 ]
        let strengthValues = Mnemonic.Strength.allValues
        
        for (strength, wordCount) in zip(strengthValues, wordCounts) {
            print("Mnemonic with \(wordCount) words; \(strength)")
            
            let mnemonic = try Mnemonic(strength: strength)
            
            XCTAssertEqual(mnemonic.words.count, wordCount)
        }
    }
}
