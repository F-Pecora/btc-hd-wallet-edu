# btc-hd-wallet-edu

A step-by-step educational Python script that reconstructs a Bitcoin HD wallet from scratch — from raw entropy to a Native SegWit address (`bc1q`).

No black boxes. Every byte is shown, every operation explained.

---

## What this covers

```
os.urandom(32)
    ↓  256 bits of entropy
    ↓  SHA256 checksum (8 bits) → 264 bits
    ↓  24 groups of 11 bits → 24 BIP39 words

24 mnemonic words
    ↓  PBKDF2-HMAC-SHA512 (2048 iterations)
512-bit seed (64 bytes)

    ↓  HMAC-SHA512(key="Bitcoin seed", msg=seed)
Master private key (32 bytes) + Master chain code (32 bytes)

    ↓  BIP32 derivation path: m/84'/0'/0'/0/index
    ↓  Each level: HMAC-SHA512(chain_parent, pubkey_parent + index)
    ↓  child_key = (IL + parent_key) mod n
Address private key (32 bytes)

    ↓  Scalar multiplication k × G on secp256k1
    ↓  double-and-add algorithm (~256 operations)
Compressed public key (33 bytes)

    ↓  SHA256 → RIPEMD160 (hash160, 20 bytes)
    ↓  Bech32 encode (witness v0, hrp="bc")
Native SegWit address ✓  bc1q...
```

Each step prints intermediate values in hex, binary, and decimal — so you can follow exactly what happens to your data at every stage.

---

## Standards implemented

| Standard | Role |
|----------|------|
| [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) | Mnemonic generation (entropy → 24 words) |
| [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) | Hierarchical Deterministic wallet (key derivation) |
| [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) | Derivation path for Native SegWit (`m/84'/0'/0'`) |
| [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) | Elliptic curve for private → public key |
| [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | Address encoding (`bc1q...`) |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/btc-hd-wallet-edu
cd btc-hd-wallet-edu
pip install -r requirements.txt
python wallet.py
```

Python 3.10+ recommended.

---

## Dependencies

```
mnemonic   — BIP39 word list and mnemonic generation
ecdsa      — secp256k1 elliptic curve scalar multiplication
bech32     — Bech32 encoding for Native SegWit addresses
```

Everything else (`hashlib`, `hmac`, `struct`, `os`) is Python standard library.

No API calls. No network requests. Runs fully offline.

---

## Output example

```
════════════════════════════════════════════════════════
  ÉTAPE 2 — Checksum SHA256 + découpage en 24 mots (BIP39)
════════════════════════════════════════════════════════

  264 bits (entropie + checksum) :
  Chaîne binaire complète (264 bits) :
    10011011111  |  00111000100  |  00000011011  |  10111111111
    ...

  Groupe  0 : 10011011111 = 1247 → "orbit"
  Groupe  1 : 00111000100 =  452 → "decade"
  ...

════════════════════════════════════════════════════════
  ÉTAPE 5 — Courbe elliptique secp256k1 : clé privée → clé publique
════════════════════════════════════════════════════════

  K = k × G (résultat, coordonnées du point) :
  Kx = 0x3fdaf6afa28c0cbe63175a5c027b7e5d...
  Ky = 0x9c3f1a2b4e8d7f6c5a2b3e4f5a6b7c8d...

  Ky est impair → préfixe = 0x03
  Clé publique compressée (33 bytes) :
    0: 03 3f da f6 af a2 8c 0c be 63 17 5a 5c 02 7b 7e
   16: 5d 62 ba 93 b5 e8 a9 ba 85 2e ae 99 62 86 ad 70
   32: b8

  → Adresse Native SegWit : bc1q3m60zatgf5hvq2frrg3xu5rps5dugnmgrynkyt
```

---

## Security notice

> **This script is for educational purposes only.**
>
> It prints private keys in plaintext to the terminal.
> Never use it with real funds or enter your actual seed phrase into it.
> On a Ledger or any hardware wallet, the private key never leaves the Secure Element — that is the entire point of hardware wallets.

---

## Concepts explained in the script

- What a bit and a byte are, and how they relate
- How 256 bits of entropy become 24 human-readable words
- Why PBKDF2 uses 2048 iterations (brute force resistance)
- What HMAC-SHA512 does and why "Bitcoin seed" is the key
- Elliptic curve geometry: point addition, point doubling
- The double-and-add algorithm for scalar multiplication
- Why `k × G` is a one-way function (discrete logarithm problem)
- Normal vs hardened BIP32 derivation and their security trade-offs
- Public key compression (why 33 bytes instead of 64)
- SHA256 + RIPEMD160 pipeline and why two hash algorithms
- Bech32 encoding and the anatomy of a `bc1q` address

---

## License

MIT
