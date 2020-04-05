import Foundation
import Crypto

public enum WordList: String {
    case chinese
    case english
    case japanese

    fileprivate var words: [String] {
        switch self {
        case .chinese  :return MnemonicWordList_Chinese
        case .english  :return MnemonicWordList_English
        case .japanese :return MnemonicWordList_Japanese
        }
    }
}

extension WordList {
    /**
     * - note: Make `internal`.
     *
     * Generate a set of random words. The number of words generated depends on
     * `entropy`; the higher it is, the more words that are generated.
     *
     * - parameter entropy
     * - returns: A list of _words_, also known as a mnemonic, or **seed phrase**.
     */
    public func randomWords<Entropy: EntropyGenerator>(withEntropy generator: Entropy) throws -> [String] {
        let concatenatedBits = try generator.entropy().get().concatenatedBits()
        let words = self.words
        
        var mnemonic: [String] = []
        for index in 0..<(concatenatedBits.count / 11) {
            let startIndex = concatenatedBits.index(concatenatedBits.startIndex, offsetBy: index * 11)
            let endIndex = concatenatedBits.index(startIndex, offsetBy: 11)
            let wordIndex = Int(strtoul(String(concatenatedBits[startIndex..<endIndex]), nil, 2))
            mnemonic.append(String(words[wordIndex]))
        }
        
        return mnemonic
    }
}

extension Data {
    /**
     * https://github.com/D-Technologies/EthereumKit/blob/master/EthereumKit/Mnemonic/Mnemonic.swift#L17     *
     */
    fileprivate func concatenatedBits() -> String {
        var sha256 = SHA256()
        sha256.update(data: self)

        let entropyBits = String(flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let hashBits    = sha256.finalize().flatMap { ("00000000" + String($0, radix: 2)).suffix(8) }
        let checkSum    = String(hashBits.prefix((count * 8) / 32))
        return (entropyBits + checkSum)
    }
}
