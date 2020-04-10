import BIP32

extension KeyIndex {
    public static let min :KeyIndex = .normal(0)
    public static let max :KeyIndex = .normal(0x80000000)
}

extension Range where Bound == KeyIndex {
    public static func hardened<Index: BinaryInteger>(_ bounds: Range<Index>) -> Range<Bound> {
        Range<Bound>(uncheckedBounds: (lower: .hardened(bounds.lowerBound), upper: .hardened(bounds.upperBound)))
    }
    
    public static func normal<Index: BinaryInteger>(_ bounds: Range<Index>) -> Range<Bound> {
        Range<Bound>(uncheckedBounds: (lower: .normal(bounds.lowerBound), upper: .normal(bounds.upperBound)))
    }
}
