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
}
