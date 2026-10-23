# CryptileCore

The auditable crypto core of [Cryptile](https://cryptile.app), an encrypted photo, video and document vault for iPhone and iPad. Pure Swift on Apple CryptoKit/CommonCrypto; no third-party dependencies, no network.

**Why this is public:** a vault app's security claims should be checkable. This repository is what the app ships, with the byte-level specification and the test vectors that prove the Swift matches it. It is published for audit: read it, run it, break it, tell us. It is not licensed for reuse in other products (see LICENSE).

- `reference/cryptile_ref.py` is the executable specification. It generates `reference/vectors.json`.
- `CryptileCore/` is the Swift package. `swift test` proves byte-equality with the vectors on every change (see the workflow).
- `docs/THREAT-MODEL.md` says what the design protects against, what it does not, and what we tell users.

## Try the beta

Cryptile is in TestFlight while we finish it: https://testflight.apple.com/join/Cj14H3HY
(if the link says the beta is unavailable, Apple is still reviewing the latest build).
Testers who send real feedback get Cryptile Plus for life at launch. Details, and what to
test, at https://cryptile.app/beta/.

## The construction, in one screen

```
pattern     = grid(1) || cells*                       drawn on a 4x4 (or 5x5) grid, >= 4 cells, no repeats
S_device    = 32 random bytes in the Keychain (ThisDeviceOnly); never in the container or a backup
PK          = PBKDF2-HMAC-SHA512(pattern, S_device || "cryptile-v1-pattern", 600 000, 64)
K_lookup    = HKDF(PK, "cryptile/v1/lookup")          K_wrap = HKDF(PK, "cryptile/v1/wrap")
slot name   = hex(HMAC-SHA256(K_lookup, "cryptile/v1/index-name"))[:32]      (no vault list exists)
MK          = 32 random bytes per vault; K_file/K_index/K_thumb = HKDF(MK, "cryptile/v1/<name>")
RK          = 12 random bytes -> 9 BIP39 words (96 bits + 3-bit checksum)
index blob  = seal(K_wrap, INDEX, wrapMK(K_wrap) || JSON{v, recovery_salt, mk_recovery, entries, ...})
recovery    = seal(HKDF(RK, "cryptile/v1/recovery-slot"), INDEX, MK || JSON)   (phrase alone restores)
small blob  = "CTL1" || ver || type || nonce12 || AES-256-GCM(pad64K(plain), aad = header)
file blob   = "CTL1" || ver || FILE || fileNonce8 || [u32 len || AES-GCM(chunk_i, nonce = fileNonce||i, aad = header||i||last)]*
```

Decoy index-shaped blobs keep the slot count uninformative; padding hides sizes. See the threat model for the limits, stated plainly.

## Verify it yourself

```sh
pip install cryptography mnemonic
python3 reference/cryptile_ref.py          # self-test, regenerates vectors.json
cd CryptileCore && swift test              # every vector must pass (macOS, Xcode 16+)
```

Reports of anything wrong: security@cryptile.app (or open an issue). We publish what we fix.

PolyForm Noncommercial License 1.0.0: free to read, run, test and verify; not for commercial reuse. Copyright Brelsford Software LLC.
