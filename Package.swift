// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "WalletKit",
    platforms: [
      .macOS(.v10_15),
      .iOS(.v13),
    ],
    products: [
      .library(name: "WalletKit", targets: ["WalletKit"]),
    ],
    dependencies: [
        // 🔢 Arbitrary-precision arithmetic in pure Swift
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.0.0"),
        
        // 🔑 Hashing (BCrypt, SHA2, HMAC), encryption (AES), public-key (RSA), and random data generation.
        .package(path: "./Sources/CryptoCore"),
    ],
    targets: [
        // 📚 -- Mnemonic code for generating deterministic keys
        .target(name: "BIP39", dependencies: [
            "CryptoCore"
        ]),
        
        // 💰 -- Hierarchical Deterministic Wallets
        .target(name: "BIP32", dependencies: [
            "CryptoCore",
            "BigInt",
        ]),

        // 🏦 -- Multi-Account Hierarchy for Deterministic Wallets
        .target(name: "BIP44", dependencies: [
            "BIP32"
        ]),

        // 🧰 -- The main event!
        .target(name: "WalletKit", dependencies: [
            "BIP39",
            "BIP44" /* incl. BIP32 */,
        ]),

        // Testing
        .target(name: "XCTHelpers", dependencies:[
            "WalletKit",
        ]),

        // Test -- BIP39
        .testTarget(name: "BIP39Tests", dependencies: [
            "XCTHelpers",
        ]),
        
        // Test -- BIP32
        .testTarget(name: "BIP32Tests", dependencies: [
            "XCTHelpers",
        ]),

        // Test -- BIP44
        .testTarget(name: "BIP44Tests", dependencies: [
            "XCTHelpers",
        ]),
    ]
)

