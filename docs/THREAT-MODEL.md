# Cryptile — Threat Model (v1)

Published with the app. If a claim here is wrong, that is a bug we fix publicly.

## Assets
Vault contents (photos, videos, documents, notes), the fact that a given vault exists, the
number of vaults, file sizes/counts, recovery phrases, Cryptile Send identity keys.

## What Cryptile protects against

| Attacker | Has | Outcome |
|---|---|---|
| Someone holding your unlocked phone | the app open | Sees only the vault whose pattern they know. No vault list. A decoy vault looks identical to a real one. |
| Someone with your phone, locked | device | Nothing; the container is AES-256-GCM ciphertext and the device salt is in the Keychain behind the passcode/Secure Enclave. |
| Forensic extraction of the app container (no Keychain) | all blobs | Ciphertext only. Cannot brute-force patterns: the KDF salt (`S_device`) is not in the container. Cannot learn file sizes (64 KiB padding) or vault count (≥8 index-shaped slots, half of which are random). |
| Forensic extraction with Keychain (passcode known / SE bypass) | blobs + `S_device` | Can brute-force the pattern offline at ~600k SHA-512 per guess. A 6-cell 4×4 pattern is ~5.7M sequences (≈2²²) — minutes on a GPU. **This is the known weak point of any pattern-based vault, including Vaultaire's.** Mitigations: encourage ≥8 cells (≈2³¹), 5×5 grid, optional biometry gate on `S_device`, panic pattern. We say this out loud rather than pretend a drawn shape is a passphrase. |
| iCloud (Apple, subpoena, breach) | backup records | Ciphertext + recovery salts. No keys. Restore needs the 9-word phrase (96 bits). |
| Us (the developer) | nothing | We run no server and hold no keys. We cannot reset access. |
| Cryptile Send: carrier/Apple in transit | attachment | AES-256-GCM under a per-message key wrapped to the recipient's X25519 key; iMessage's own E2E on top. |
| Cryptile Send: recipient | plaintext in their vault | View-once/expiry/no-save are enforced by the recipient's app only. A screenshot or a jailbroken device defeats them; we detect screenshots after the fact and tell the sender. We do not claim DRM. |

## What Cryptile does not protect against
- A compromised/jailbroken device with malware reading memory while a vault is open.
- Shoulder-surfing the pattern. (Pattern input hides the trail by default.)
- The user losing both the device and the phrase. There is no recovery. By design.
- Traffic analysis of iMessage (who messaged whom, when). Not our layer.
- Weak patterns under offline attack when the Keychain is also compromised (see table).

## Cryptographic claims (verifiable)
- Executable spec: `reference/cryptile_ref.py`; Swift conformance: `CryptileCore/Tests` against
  `vectors.json`. Any divergence is a failing test.
- AES-256-GCM with 96-bit nonces: random for small blobs (per-vault blob count ≪ 2³² so
  collision probability is negligible); structured `fileNonce8‖counter` for file chunks so a
  file key is never reused with the same nonce across chunks.
- Key separation by HKDF info strings; no key is used for two purposes.
- Authentication covers headers (type/version) and chunk position/finality.

## Known leaks we accept and disclose
- Total container size (bucketed, but a 10 GB vault is visibly not 10 MB).
- Number of index-shaped slots ≥ 8 reveals an upper bound on vaults, not the count.
- Timing of writes (filesystem mtimes). We touch decoys on every write to blur this.

## Audit plan
- Day 0: spec + reference + vectors public on GitHub (Apache-2.0 for CryptileCore).
- Day 30: solicit review (Cure53 / Trail of Bits quote; or a public bounty if cost > $5k).
- Ongoing: `SECURITY.md` with a disclosure address and 90-day fix commitment.
