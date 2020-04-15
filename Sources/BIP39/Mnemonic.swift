import CryptoCore

/**
 * A list of words which can generate a private key.
 */
public struct Mnemonic: Equatable {
    /// The list of words as a single sentence.
    public private(set) var phrase :String = ""

    /// The list of words.
    public var words :[String] {
        phrase.split(separator: " ").map(String.init)
    }
    
    /**
     * Create a mnemonic from a list of `words`.
     *
     * - parameter words: An array of words.
     */
    fileprivate init<Words: Collection>(words: Words) throws where Words.Element: StringProtocol {
        guard Int.wordCounts.contains(words.count) else {
            throw SeedDerivatorError.seedPhraseInvalid(words.joined(separator: " "))
        }
        self.phrase = words.joined(separator: " ")
    }

    /**
     * Create a mnemonic from a pre-computed `entropy`, with phrase_ pulled from
     * the `vocabulary` list.
     *
     * - parameter entropy
     * - parameter vocabulary
     */
    public init<Entropy: EntropyGenerator>(entropy: Entropy, in vocabulary: WordList = .english) throws {
        self = try Mnemonic(words: try vocabulary.randomWords(withEntropy: entropy))
    }

    /**
     * Create the mnemonic's private key (seed).
     *
     * - warning: Calling this function can take some time. Avoid calling
     *            this function from the main thread, when possible.
     *
     * **BIP39**:
     *
     * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
     *
     * - parameter passphrase: Associates a secret (for extra security).
     * - parameter derivator: The `SeedDerivator` used to derived the seed.
     *
     * - returns: A _result_ with the seed's bytes, or an `Error`.
     */
    public func seed(passphrase: String = "", derivator: SeedDerivator.Type = DefaultSeedDerivator.self) -> Result<Data, SeedDerivatorError> {
        derivator.derivedSeed(fromPassword: self.phrase, salt: "mnemonic" + passphrase)
    }
}

extension Mnemonic {
    public init(seedPhrase phrase: String?) throws {
        if let phrase = phrase {
            try self.init(words: phrase.split(separator: " "))
        }
        else {
            try self.init()
        }
    }
    
    public init(strength: Int = .strongest, in vocabulary: WordList = .english) throws {
        try self.init(entropy: strength, in: vocabulary)
    }
}
