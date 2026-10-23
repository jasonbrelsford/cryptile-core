#!/usr/bin/env python3
"""
Cryptile crypto construction v1 — executable reference implementation.

This file IS the specification. The Swift package (CryptileCore) must produce
byte-identical output for every vector in vectors.json, which this file
generates. Anything the Swift code does that this file does not do is a bug
in one of them.

Primitives (all standard, all available in Apple CryptoKit / CommonCrypto):
  PBKDF2-HMAC-SHA512   pattern -> pattern key (slow, device-salted)
  HKDF-SHA256          every subkey derivation (domain-separated by info)
  AES-256-GCM          every ciphertext (files, index, key wraps)
  HMAC-SHA256          index-slot naming (lookup without a vault list)

Run:  python3 -I cryptile_ref.py            # self-test + regenerate vectors.json
"""
import json, os, struct, hashlib, hmac, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic

VERSION = 1
MAGIC = b"CTL1"
PBKDF2_ITERATIONS = 600_000          # canonical; tests may use TEST_ITERATIONS
TEST_ITERATIONS = 1_000
PAD_BUCKET = 64 * 1024               # every blob is padded to a multiple of this
CHUNK = 1024 * 1024                  # file plaintext chunk size (STREAM construction)
MIN_INDEX_SLOTS = 8                  # container always shows >= this many index blobs

# Blob types (1 byte in header)
T_INDEX, T_FILE, T_THUMB, T_DECOY = 1, 2, 3, 4

# ---------------------------------------------------------------- KDFs

def pattern_bytes(cells):
    """A drawn pattern is an ordered list of grid cell indices (0..grid*grid-1).
    Serialized as: grid size (1 byte) || one byte per cell."""
    grid = cells["grid"]; seq = cells["cells"]
    assert 3 <= grid <= 8 and len(seq) >= 4 and all(0 <= c < grid*grid for c in seq)
    assert len(set(seq)) == len(seq), "cells may not repeat"
    return bytes([grid]) + bytes(seq)

def pattern_key(pattern, device_salt, iterations=PBKDF2_ITERATIONS):
    """PK = PBKDF2-HMAC-SHA512(pattern, device_salt || 'cryptile-v1-pattern', iters, 64)
    device_salt: 32 random bytes that live ONLY in the Keychain (ThisDeviceOnly).
    It is never written into the container or the backup, so an offline attacker
    with the container alone cannot even start guessing patterns."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64,
                     salt=device_salt + b"cryptile-v1-pattern", iterations=iterations)
    return kdf.derive(pattern_bytes(pattern))

def hkdf(ikm, info, length=32, salt=b""):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None,
                info=info).derive(ikm)

def lookup_key(pk):   return hkdf(pk, b"cryptile/v1/lookup")
def wrap_key(pk):     return hkdf(pk, b"cryptile/v1/wrap")
def index_slot_name(k_lookup):
    """Name of this vault's index blob inside the container. Nothing else in the
    container points at it; without the pattern there is no vault list."""
    return hmac.new(k_lookup, b"cryptile/v1/index-name", hashlib.sha256).hexdigest()[:32]

# per-vault subkeys from the random master key MK
def file_key(mk):     return hkdf(mk, b"cryptile/v1/file")
def index_key(mk):    return hkdf(mk, b"cryptile/v1/index")
def thumb_key(mk):    return hkdf(mk, b"cryptile/v1/thumb")
def search_key(mk):   return hkdf(mk, b"cryptile/v1/search")   # reserved: 1.1 on-device search index
def share_key(mk):    return hkdf(mk, b"cryptile/v1/share")    # reserved: 1.2 family sharing

# ---------------------------------------------------------------- padding

def pad(data, bucket=PAD_BUCKET):
    """ISO/IEC 7816-4: append 0x80 then zeros to the next bucket boundary.
    Hides true sizes; a 3 KB note and a 60 KB photo are the same blob size."""
    n = len(data) + 1
    total = ((n + bucket - 1) // bucket) * bucket
    return data + b"\x80" + b"\x00" * (total - n)

def unpad(data):
    i = data.rstrip(b"\x00")
    assert i.endswith(b"\x80"), "bad padding"
    return i[:-1]

# ---------------------------------------------------------------- blobs

def header(btype):
    return MAGIC + bytes([VERSION, btype])

def seal_blob(key, btype, plaintext, nonce):
    """Small-blob format (index, thumbs, key wraps):
       header(6) || nonce(12) || AES-256-GCM(pad(plaintext), aad=header)"""
    h = header(btype)
    ct = AESGCM(key).encrypt(nonce, pad(plaintext), h)
    return h + nonce + ct

def open_blob(key, blob):
    h, nonce, ct = blob[:6], blob[6:18], blob[18:]
    assert h[:4] == MAGIC and h[4] == VERSION
    return h[5], unpad(AESGCM(key).decrypt(nonce, ct, h))

def seal_file(key, plaintext, file_nonce8):
    """Large-file STREAM construction. Plaintext split into CHUNK-size pieces;
       chunk i uses nonce = file_nonce8 || u32be(i), aad = header || u32be(i) || last(1).
       Only the final chunk is padded. Truncation / reordering fails authentication.
       Layout: header(6) || file_nonce8 || [u32be(ctlen) || ct]*"""
    h = header(T_FILE)
    out = bytearray(h + file_nonce8)
    chunks = [plaintext[i:i+CHUNK] for i in range(0, len(plaintext), CHUNK)] or [b""]
    for i, c in enumerate(chunks):
        last = i == len(chunks) - 1
        nonce = file_nonce8 + struct.pack(">I", i)
        aad = h + struct.pack(">I", i) + bytes([1 if last else 0])
        ct = AESGCM(key).encrypt(nonce, pad(c) if last else c, aad)
        out += struct.pack(">I", len(ct)) + ct
    return bytes(out)

def open_file(key, blob):
    h, fn, pos = blob[:6], blob[6:14], 14
    assert h[:4] == MAGIC and h[4] == VERSION and h[5] == T_FILE
    out, i = bytearray(), 0
    while pos < len(blob):
        (n,) = struct.unpack(">I", blob[pos:pos+4]); pos += 4
        ct = blob[pos:pos+n]; pos += n
        last = pos >= len(blob)
        aad = h + struct.pack(">I", i) + bytes([1 if last else 0])
        pt = AESGCM(key).decrypt(fn + struct.pack(">I", i), ct, aad)
        out += unpad(pt) if last else pt
        i += 1
    return bytes(out)

# ---------------------------------------------------------------- recovery phrase

_m = Mnemonic("english")
def recovery_phrase(rk12):
    """9 BIP39 words = 99 bits = 96 bits of entropy (rk12) + 3-bit SHA-256 checksum."""
    assert len(rk12) == 12
    bits = "".join(f"{b:08b}" for b in rk12) + f"{hashlib.sha256(rk12).digest()[0]:08b}"[:3]
    return " ".join(_m.wordlist[int(bits[i:i+11], 2)] for i in range(0, 99, 11))

def recovery_key_from_phrase(phrase):
    words = phrase.lower().split()
    assert len(words) == 9
    bits = "".join(f"{_m.wordlist.index(w):011b}" for w in words)
    rk = int(bits[:96], 2).to_bytes(12, "big")
    assert bits[96:] == f"{hashlib.sha256(rk).digest()[0]:08b}"[:3], "checksum"
    return rk

def recovery_key(rk12, recovery_salt16):
    return hkdf(rk12, b"cryptile/v1/recovery", salt=recovery_salt16)

# ---------------------------------------------------------------- vault index

def index_plaintext(entries, mk_wrapped_recovery, recovery_salt):
    """The index JSON. mk_wrapped_recovery lets the recovery phrase alone open the
    vault on a new device (backup restore), with no device salt."""
    doc = {"v": VERSION,
           "recovery_salt": recovery_salt.hex(),
           "mk_recovery": mk_wrapped_recovery.hex(),
           "entries": entries}
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()

def build_index_blob(pk, mk, entries, rk12, recovery_salt, nonces):
    """Index blob = seal_blob(K_wrap, T_INDEX,  wrappedMK(60) || indexJSON )
       where wrappedMK = nonce12 || AES-GCM(MK, key=K_wrap, aad='cryptile/v1/mk').
       One decryption with the pattern key yields MK and the index together."""
    k_wrap = wrap_key(pk)
    mk_wrapped = nonces["mk"] + AESGCM(k_wrap).encrypt(nonces["mk"], mk, b"cryptile/v1/mk")
    k_rec = recovery_key(rk12, recovery_salt)
    mk_rec = nonces["rec"] + AESGCM(k_rec).encrypt(nonces["rec"], mk, b"cryptile/v1/mk")
    body = mk_wrapped + index_plaintext(entries, mk_rec, recovery_salt)
    return seal_blob(k_wrap, T_INDEX, body, nonces["index"])

def open_index_blob(pk, blob):
    k_wrap = wrap_key(pk)
    t, body = open_blob(k_wrap, blob)
    assert t == T_INDEX
    # wrappedMK = nonce(12) || ct(32) || tag(16) = 60 bytes
    mk = AESGCM(k_wrap).decrypt(body[:12], body[12:60], b"cryptile/v1/mk")
    return mk, json.loads(body[60:])

def open_index_with_phrase(phrase, blob_body_json):
    """Restore path: given the (already-opened or candidate) index JSON, the
    recovery phrase alone yields MK. For restore from backup the app tries K_rec
    against mk_recovery of every index slot; AES-GCM auth failure = not ours."""
    rk = recovery_key_from_phrase(phrase)
    salt = bytes.fromhex(blob_body_json["recovery_salt"])
    mk_rec = bytes.fromhex(blob_body_json["mk_recovery"])
    return AESGCM(recovery_key(rk, salt)).decrypt(mk_rec[:12], mk_rec[12:], b"cryptile/v1/mk")

# ---------------------------------------------------------------- recovery slot
# A second, index-shaped blob per vault that the recovery phrase ALONE opens (no pattern,
# no device salt). This is what makes restore-from-backup on a new device possible: the
# pattern-sealed index above cannot be opened without the device salt, by design.

def recovery_slot_key(rk12):    return hkdf(rk12, b"cryptile/v1/recovery-slot")
def recovery_slot_name(rk12):
    lookup = hkdf(rk12, b"cryptile/v1/recovery-lookup")
    return hmac.new(lookup, b"cryptile/v1/recovery-name", hashlib.sha256).hexdigest()[:32]

def build_recovery_slot(rk12, mk, index_json_bytes, nonce):
    """recovery blob = seal_blob(K_slot, T_INDEX, MK(32) || indexJSON). Index-shaped, so it is
    indistinguishable from an index or a decoy slot without RK."""
    return seal_blob(recovery_slot_key(rk12), T_INDEX, mk + index_json_bytes, nonce)

def open_recovery_slot(rk12, blob):
    t, body = open_blob(recovery_slot_key(rk12), blob)
    assert t == T_INDEX
    return body[:32], json.loads(body[32:])

# ---------------------------------------------------------------- vectors

def H(b): return b.hex()

def make_vectors():
    V = {"version": VERSION, "notes": __doc__.strip().splitlines()[0]}
    device_salt = bytes(range(32))
    pattern = {"grid": 4, "cells": [0, 5, 10, 15, 14, 13]}          # a diagonal + hook
    mk = bytes.fromhex("a1" * 32)
    rk = bytes.fromhex("0123456789abcdef01234567")
    rsalt = bytes.fromhex("ff" * 16)
    nonces = {"mk": bytes.fromhex("01" * 12), "rec": bytes.fromhex("02" * 12),
              "index": bytes.fromhex("03" * 12)}
    file_nonce = bytes.fromhex("0a0b0c0d0e0f1011")

    V["pattern"] = {"input": pattern, "bytes": H(pattern_bytes(pattern))}
    V["device_salt"] = H(device_salt)
    for name, iters in (("fast", TEST_ITERATIONS), ("canonical", PBKDF2_ITERATIONS)):
        pk = pattern_key(pattern, device_salt, iters)
        V[f"pattern_key_{name}"] = {"iterations": iters, "pk": H(pk),
                                    "k_lookup": H(lookup_key(pk)), "k_wrap": H(wrap_key(pk)),
                                    "index_slot_name": index_slot_name(lookup_key(pk))}
    pk = pattern_key(pattern, device_salt, TEST_ITERATIONS)   # fast PK used below

    V["subkeys"] = {"mk": H(mk), "file": H(file_key(mk)), "index": H(index_key(mk)),
                    "thumb": H(thumb_key(mk)), "search": H(search_key(mk)), "share": H(share_key(mk))}

    V["padding"] = [{"in": H(b"hello"), "out_len": len(pad(b"hello")),
                     "out_sha256": hashlib.sha256(pad(b"hello")).hexdigest()},
                    {"in_len": PAD_BUCKET - 1, "out_len": len(pad(b"x" * (PAD_BUCKET - 1)))},
                    {"in_len": PAD_BUCKET, "out_len": len(pad(b"x" * PAD_BUCKET))}]

    small = b"Cryptile small blob test"
    V["blob_thumb"] = {"plain": H(small), "nonce": H(nonces["index"]),
                       "blob_sha256": hashlib.sha256(seal_blob(thumb_key(mk), T_THUMB, small, nonces["index"])).hexdigest(),
                       "blob_prefix": H(seal_blob(thumb_key(mk), T_THUMB, small, nonces["index"])[:40])}

    # file: 1.5 chunks so the STREAM path with a non-final chunk is exercised
    big = bytes((i * 7 + 3) & 0xff for i in range(CHUNK + CHUNK // 2))
    fb = seal_file(file_key(mk), big, file_nonce)
    assert open_file(file_key(mk), fb) == big
    V["file_blob"] = {"plain_len": len(big), "plain_sha256": hashlib.sha256(big).hexdigest(),
                      "file_nonce": H(file_nonce), "blob_len": len(fb),
                      "blob_sha256": hashlib.sha256(fb).hexdigest(), "blob_prefix": H(fb[:48])}
    empty = seal_file(file_key(mk), b"", file_nonce)
    assert open_file(file_key(mk), empty) == b""
    V["file_blob_empty"] = {"blob_len": len(empty), "blob_sha256": hashlib.sha256(empty).hexdigest()}

    phrase = recovery_phrase(rk)
    assert recovery_key_from_phrase(phrase) == rk
    V["recovery"] = {"rk": H(rk), "phrase": phrase, "salt": H(rsalt),
                     "k_recovery": H(recovery_key(rk, rsalt))}

    entries = [{"id": "e1", "name": "IMG_0001.heic", "mime": "image/heic", "size": 123456,
                "created": 1760000000, "blob": "3f2a", "thumb": "9c1d"}]
    ib = build_index_blob(pk, mk, entries, rk, rsalt, nonces)
    mk2, doc = open_index_blob(pk, ib)
    assert mk2 == mk and doc["entries"] == entries
    assert open_index_with_phrase(phrase, doc) == mk
    V["index_blob"] = {"entries": entries, "nonces": {k: H(v) for k, v in nonces.items()},
                       "blob_len": len(ib), "blob_sha256": hashlib.sha256(ib).hexdigest(),
                       "blob_hex": H(ib)}      # full hex so Swift can decrypt it directly

    # recovery slot: the same index JSON, sealed so the phrase alone opens it
    doc_bytes = ib and json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()
    rs_nonce = bytes.fromhex("04" * 12)
    rs = build_recovery_slot(rk, mk, doc_bytes, rs_nonce)
    mk3, doc3 = open_recovery_slot(rk, rs)
    assert mk3 == mk and doc3 == doc
    V["recovery_slot"] = {"name": recovery_slot_name(rk), "k_slot": H(recovery_slot_key(rk)),
                          "nonce": H(rs_nonce), "blob_len": len(rs),
                          "blob_sha256": hashlib.sha256(rs).hexdigest(), "blob_hex": H(rs)}
    return V

def self_test():
    V = make_vectors()
    # negative tests: wrong pattern, tampered byte, truncated file
    device_salt = bytes(range(32)); pattern = {"grid": 4, "cells": [0, 5, 10, 15, 14, 13]}
    pk = pattern_key(pattern, device_salt, TEST_ITERATIONS)
    wrong = pattern_key({"grid": 4, "cells": [0, 5, 10, 15, 14, 12]}, device_salt, TEST_ITERATIONS)
    ib = bytes.fromhex(V["index_blob"]["blob_hex"])
    from cryptography.exceptions import InvalidTag
    try: open_index_blob(wrong, ib); raise SystemExit("wrong pattern opened the index")
    except InvalidTag: pass
    t = bytearray(ib); t[30] ^= 1
    try: open_index_blob(pk, bytes(t)); raise SystemExit("tampered index opened")
    except InvalidTag: pass
    mk = bytes.fromhex("a1" * 32)
    fb = seal_file(file_key(mk), b"A" * (CHUNK + 10), bytes(8))
    try: open_file(file_key(mk), fb[:14 + 4 + CHUNK + 16]); raise SystemExit("truncated file opened")
    except InvalidTag: pass   # first chunk re-read as 'last' -> aad mismatch -> auth fails
    assert index_slot_name(lookup_key(pk)) != index_slot_name(lookup_key(wrong))
    print("self-test OK")
    return V

if __name__ == "__main__":
    V = self_test()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
    with open(out, "w") as f: json.dump(V, f, indent=1)
    print("wrote", out, len(json.dumps(V)), "bytes")
