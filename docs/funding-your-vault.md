# Funding your vault

> Prototype warning: vault.js has not been audited. Practise this whole guide on testnet or signet first. Do not put real savings behind it until the volunteer review is done.

## The one thing to understand

Coins never go *into* vault.js. Bitcoin always stays on the blockchain.
vault.js protects the **seed** (the 24 words), which is the key that controls those coins.
So "funding the vault" means: send bitcoin to an address that belongs to the seed vault.js protects.

## Example: Sue and Bob

**Sue (the owner) sets it up**

1. Boot Tails and keep it offline.
2. Run vault.js `node vault.js create --show`. It makes a new 24-word seed, encrypts it with your passphrase, and splits it into 5 shares (any 3 recover it).
3. Before you wipe anything, open **Sparrow Wallet** (it comes with Tails), choose *New Wallet*, then *Import* with those 24 words.
   - Write down the wallet's **xpub** (the public key that lets you see the wallet) and copy the first **receive address** onto paper or a USB stick.
   - The xpub and addresses are safe to copy. The 24 words are not.
4. Close Sparrow without saving the wallet, then shut down Tails. Tails forgets everything.
5. Hand out the 5 shares as planned in the heir runbook.

**Sue sends the coins**

6. On her normal computer or phone, Sue opens Sparrow and makes a **watch-only** wallet from the xpub. It shows the balance but cannot spend.
7. She sends a **small test amount** from her exchange or current wallet to the receive address.
8. Once it confirms, she does a test recovery (step 10 below, with 3 shares) and checks Sparrow shows the same address and balance. Only then does she send the rest.
9. For each later deposit, she uses the next unused receive address from the watch-only wallet.

**Bob (the heir) recovers**

10. Bob boots Tails offline, gathers 3 of the 5 shares and the passphrase, and runs vault.js `node vault.js reconstruct --show share1 share2 share3`. It gives back the 24 words.
11. Bob restores the 24 words into a new hardware wallet (bought direct from the maker) and sends the coins to his own wallet from there. Never connect a machine that has the words on it.
12. Bob then treats the old seed as used and never relies on it again.

## Safety checklist

- Never type the 24 words on an online computer, phone, website or chat.
- Never photograph the words or the shares.
- Always do a small test deposit and a test recovery first.
- The watch-only wallet can see coins but can never spend them, so it is safe on an everyday device.
- No one from BTCGuardiansHQ will ever ask for your seed, shares or passphrase.
