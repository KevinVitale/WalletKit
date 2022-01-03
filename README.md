<img src="WalletKit.png" />

## Platforms
- **macOS**, v10.15+;
- **iOS**, v13+;
- **Linux**

### CLI Utility
[This CLI utility](https://github.com/KevinVitale/WalletKitCLI) is cross-platform, and demonstrates a portion of this framework's functionality.

## Adding `WalletKit` as a Dependency
To use the `WalletKit` library in a Swift Package Manager (SPM) project, add the following line to the _dependencies_ in you `Package.swift` file:
    
```swift
.package(url: "https://github.com/KevinVitale/WalletKit", from: "0.0.3"),
```

The `WalletKit` library is under active development, and while attempts are made to maintain source-stability, this is not guaranteed between minor versions. You may specify `.upToNextMinor(from:)`, instead of `from(_:)`, if you need to be at a specific version.

## Usage

```swift
import WalletKit

let wallet  = try Mnemonic().createWallet()
let account = try wallet.account(coinType: .ETH, atIndex: 0)

// 'Normal' addresses...
account[.normal(0..<10)].forEach { 
    print($0.address)
}

// 'Hardened' addresses...
account[.hardened(0..<10)].forEach { 
    print($0.address)
}
```


## Examples

```swift
let mnemonic = try Mnemonic()
  print(mnemonic.phrase)

  let accounts = try mnemonic.createWallet().account(coinType: .ETH, atIndex: 0)
  accounts[.hardened(0..<10)].enumerated().forEach { (index, account) in
    let address = account.address
    let privateKey = "0x" + account.privateKey.key.dropFirst().hexString
    
    print("[idx: \(index)]", address, privateKey)
  }
}

// Console output
<24-word seed phrase>
[idx: 0] 0x95e18dd2115c49651a5195cdaed1e4589d9a882d 0x...privatekey...
[idx: 1] 0x70c52be490029822278eecf2d9e4324c6e0505b8 0x...privatekey...
[idx: 2] 0x11194b63c701ba9612d8b4c29e9d34127160043c 0x...privatekey...
[idx: 3] 0x90ec34dd860c4e2876ea3e2ce3f7362d6ef9c8b5 0x...privatekey...
[idx: 4] 0x3a0a814ad24e703aae2b1acb2211dba4dab7330f 0x...privatekey...
[idx: 5] 0x9cc103ff117e604fbf5fee3d4b90b2646576190f 0x...privatekey...
[idx: 6] 0x263c0757284090a3ceec27243d483399bbc0a570 0x...privatekey...
[idx: 7] 0x645b93bda895c130451b5e20341130665f693c53 0x...privatekey...
[idx: 8] 0x14b6fdfdbe37fbcd6a2e4a6f85a303bcc8327552 0x...privatekey...
[idx: 9] 0xffd4e7a268a8cf75f4215f06a8ebc049195c1b4e 0x...privatekey...
```

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
