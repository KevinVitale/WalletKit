<img src="WalletKit.png" />

## Platforms
- **macOS**, v10.15+;
- **iOS**, v13+;
- **Linux**

## Usage

```swift
import WalletKit

let wallet  = try Mnemonic().wallet()
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
