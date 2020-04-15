import Foundation

/**
 * Adopters can generate entropy; a random set of bytes.
 */
public protocol EntropyGenerator {
    func entropy() -> Result<Data,Error>
}

/**
 * Errors relating to `EntropyGenerator`.
 */
public enum EntropyGeneratorError: Swift.Error {
    case invalidInput(EntropyGenerator)
}

extension Int: EntropyGenerator {
    public func entropy() -> Result<Data, Swift.Error> {
        guard (self % 2) == 0, case 4...8 = (self / 32) else {
            return .failure(EntropyGeneratorError.invalidInput(self))
        }
        return Result { try Data.randomBytes(self / 8) }
    }
    
    static var wordCounts: [Int] {
        [ 12, 15, 18, 21, 24 ]
    }
    
    public static var weakest   : Int { 128 }
    public static var weak      : Int { 160 }
    public static var medium    : Int { 192 }
    public static var strong    : Int { 224 }
    public static var strongest : Int { 256 }
}

extension EntropyGenerator where Self: StringProtocol {
    /**
     * Interprets `self` as a string of pre-computed _entropy_, at least if its
     * of even length, and between 32 & 64 characters.
     *
     *  E.g., "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f".
     */
    public func entropy() -> Result<Data, Error> {
        guard (count % 2) == 0, case 4...8 = (count / 8) else {
            return .failure(EntropyGeneratorError.invalidInput(String(self)))
        }
        
        var values  = [Int32?]()
        for (idx, char) in self.enumerated() {
            // Break up `self` into character-pairs, representing a single hex.
            if idx % 2 == 1 {
                let prevIdx = self.index(before: String.Index(utf16Offset: idx, in: self))
                let prevChr = self[prevIdx]
                let value   = Scanner(string: "\(prevChr)\(char)").scanInt32(representation: .hexadecimal)
                values.append(value)
            }
        }
        return .success(Data(values.compactMap { $0 }.map(UInt8.init)))
    }
}

extension String: EntropyGenerator { }
extension String.SubSequence: EntropyGenerator { }

