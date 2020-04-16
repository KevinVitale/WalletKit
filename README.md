<img src="WalletKit.png" />

## Platforms
- **macOS**, v10.15+;
- **iOS**, v13+;
- **Linux**

## Adding `WalletKit` as a Dependency
To use the `WalletKit` library in a Swift Package Manager (SPM) project, add the following line to the _dependencies_ in you `Package.swift` file:
    
```swift
.package(url: "https://github.com/KevinVitale/WalletKit", from: "0.0.1"),
```

The `WalletKit` library is under active development, and while attempts are made to maintain source-stability, this is not guaranteed between minor versions. You may specify `.upToNextMinor(from:)`, instead of `from(_:)`, if you need to be at a specific version.

## Usage

```swift
import WalletKit

let wallet  = try Mnemonic().createWallet()
let account = try wallet.account(coinType: .ETH, atIndex: 0)

account[.normal(0..<10)].forEach { 
    print($0.address)
}
```

## Examples

### Command-Line Interface
```
USAGE: cli [--seed-phrase <seed-phrase>] [--passphrase <passphrase>]

OPTIONS:
  -s, --seed-phrase <seed-phrase>
                          A specific mnemonic seed phrase used to create the wallet. 
  -p, --passphrase <passphrase>
                          An optional passphrase for improving entropy. 
  -h, --help              Show help information.
```
