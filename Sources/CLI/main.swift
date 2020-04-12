import WalletKit
import ArgumentParser

struct CLI: ParsableCommand {

  func run() throws {
    let mnemonic = try Mnemonic(entropy: 256)
    let wallet   = try mnemonic.wallet(coinType: ETH.self).get()
    let account  = try wallet.account(atIndex: 0)

    print("Mnemonic Phrase:", mnemonic.phrase)
    account[.normal(0..<10)].forEach {
      print($0.address)
    }
  }
}

CLI.main()
