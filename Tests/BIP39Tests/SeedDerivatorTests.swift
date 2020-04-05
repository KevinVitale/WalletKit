import XCTHelpers

final class SeedDerivatorTests: XCTestCase {
    func testDummySeedDerivatorFails() throws {
        XCTAssertThrowsError(try DummySeedDerivator.derivedSeed(fromPassword: "", salt: "").get())
    }
}
