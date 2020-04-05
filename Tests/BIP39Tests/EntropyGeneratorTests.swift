import XCTHelpers

final class EntropyGeneratorTests: XCTestCase {
    func testEntropyGeneratorStringGood() throws {
        let string  = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
        let entropy = try string.entropy().get()
        XCTAssertEqual(entropy.count, 16)
    }
    
    func testEntropyGeneratorStringBad() throws {
        let string  = "7f7f7f7f7f7f7f7f" // too small
        XCTAssertThrowsError(try string.entropy().get())
    }
    
    func testEntropyGeneratorStrength() throws {
        let byteCounts     = [ 16, 20, 24, 28, 32 ]
        let strengthValues = Mnemonic.Strength.allValues
        
        for (strength, byteCount) in zip(strengthValues, byteCounts) {
            print("Entropy with \(byteCount) bytes; \(strength)")
            
            let entropy = try strength.entropy().get()
            XCTAssertEqual(entropy.count, byteCount)
        }
    }
}
