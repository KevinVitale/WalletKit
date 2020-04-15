import WalletKit
import ArgumentParser

struct CLI: ParsableCommand {
    @Option(name: .shortAndLong, help: "A specific mnemonic seed phrase used to create the wallet.")
    var seedPhrase: String?
    
    @Option(name: .shortAndLong, help: "An optional passphrase for improving entropy.")
    var passphrase: String?

    func run() throws {
        let wallet     = try Mnemonic(seedPhrase: seedPhrase).wallet(passphrase: passphrase ?? "")
        let account    = try wallet.account(coinType: .ETH, atIndex: 0)
        
        account[.normal(0..<10)].forEach { account in
            print(account.privateKey.pathURL, account.address)
        }
        
        print()
        account[.hardened(0..<10)].forEach { account in
            print(account.privateKey.pathURL, account.address)
        }
    }
}

CLI.main()
