import XCTHelpers

final class MnemonicWordListTests: XCTestCase {
    func testMnemonicWordListEnglish() throws {
        XCTAssertEqual(MnemonicWordList_English.count, 2048)
    }
    
    func testMnemonicWordListJapanese() throws {
        XCTAssertEqual(MnemonicWordList_Japanese.count, 2048)
    }
    
    func testMnemonicWordListChinese() throws {
        XCTAssertEqual(MnemonicWordList_Chinese.count, 2048)
    }
}
