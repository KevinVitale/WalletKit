import WalletKit
import ArgumentParser

struct CLI: ParsableCommand {
    @Option(name: .shortAndLong, help: "A specific mnemonic seed phrase used to create the wallet.")
    var seedPhrase: String?
    
    @Option(name: .shortAndLong, help: "An optional passphrase for improving entropy.")
    var passphrase: String?
    
    func run() throws {
        let wallet     = try Mnemonic(seedPhrase: seedPhrase).createWallet(passphrase: passphrase ?? "")
        let account    = try wallet.account(coinType: .ETH, atIndex: 0)
        
        account[.normal(0..<10)].forEach { log(account: $0) }
        account[.hardened(0..<10)].forEach { log(account: $0) }
    }
    
    private func log<Account: AccountProtocol>(account: Account) {
        print(account.privateKey.pathURL, account.address, "0x" + account.privateKey.key.dropFirst().hexString)
    }
}

CLI.main()
