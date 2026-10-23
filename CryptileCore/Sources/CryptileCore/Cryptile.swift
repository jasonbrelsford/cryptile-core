import Foundation
import CryptoKit
import Security

/// Format constants. Every number here is mirrored in reference/cryptile_ref.py.
public enum Cryptile {
    public static let version: UInt8 = 1
    public static let magic = Data("CTL1".utf8)
    /// Canonical PBKDF2 iteration count for the drawn pattern. Tests use `testIterations`.
    public static let pbkdf2Iterations = 600_000
    public static let testIterations = 1_000
    /// Every small blob and every final file chunk is padded to a multiple of this.
    public static let padBucket = 64 * 1024
    /// File plaintext chunk size for the STREAM construction.
    public static let chunk = 1024 * 1024
    /// The container always presents at least this many index-shaped blobs (real + decoy).
    public static let minIndexSlots = 8

    public enum BlobType: UInt8 {
        case index = 1, file = 2, thumb = 3, decoy = 4
    }

    static func header(_ t: BlobType) -> Data {
        magic + Data([version, t.rawValue])
    }
}

public enum CryptileError: Error, Equatable {
    case badPattern(String)
    case badFormat(String)
    case badPadding
    case authenticationFailed
    case badRecoveryPhrase(String)
}

// MARK: - Pattern

/// A drawn unlock pattern: an ordered, non-repeating list of cell indices on a grid.
/// Serialized as `grid(1) || cell*` — this byte string is the PBKDF2 "password".
public struct Pattern: Equatable, Sendable {
    public let grid: Int
    public let cells: [UInt8]

    public init(grid: Int, cells: [UInt8]) throws {
        guard (3...8).contains(grid) else { throw CryptileError.badPattern("grid must be 3...8") }
        guard cells.count >= 4 else { throw CryptileError.badPattern("at least 4 cells") }
        guard cells.allSatisfy({ Int($0) < grid * grid }) else { throw CryptileError.badPattern("cell out of range") }
        guard Set(cells).count == cells.count else { throw CryptileError.badPattern("cells may not repeat") }
        self.grid = grid; self.cells = cells
    }

    public var bytes: Data { Data([UInt8(grid)]) + Data(cells) }
}

// MARK: - Key derivation

public enum KDF {
    /// PK = PBKDF2-HMAC-SHA512(pattern.bytes, deviceSalt || "cryptile-v1-pattern", iterations, 64).
    /// `deviceSalt` lives only in the Keychain (ThisDeviceOnly). It is never written to the
    /// container or the backup, so the container alone cannot be brute-forced.
    public static func patternKey(_ pattern: Pattern, deviceSalt: Data,
                                  iterations: Int = Cryptile.pbkdf2Iterations) -> Data {
        precondition(deviceSalt.count == 32, "device salt is 32 bytes")
        let salt = deviceSalt + Data("cryptile-v1-pattern".utf8)
        return PBKDF2.sha512(password: pattern.bytes, salt: salt, iterations: iterations, length: 64)
    }

    public static func hkdf(_ ikm: Data, info: String, salt: Data = Data(), length: Int = 32) -> Data {
        let out = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm),
                                         salt: salt, info: Data(info.utf8), outputByteCount: length)
        return out.withUnsafeBytes { Data($0) }
    }

    public static func lookupKey(_ pk: Data) -> Data { hkdf(pk, info: "cryptile/v1/lookup") }
    public static func wrapKey(_ pk: Data) -> Data   { hkdf(pk, info: "cryptile/v1/wrap") }

    /// The container filename of this vault's index. No list of vaults exists anywhere;
    /// a pattern either names an index that exists or it names an empty vault.
    public static func indexSlotName(lookupKey: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data("cryptile/v1/index-name".utf8),
                                                  using: SymmetricKey(data: lookupKey))
        return String(Data(mac).hex.prefix(32))
    }

    // Per-vault subkeys from the random 32-byte master key.
    public static func fileKey(_ mk: Data) -> Data   { hkdf(mk, info: "cryptile/v1/file") }
    public static func indexKey(_ mk: Data) -> Data  { hkdf(mk, info: "cryptile/v1/index") }
    public static func thumbKey(_ mk: Data) -> Data  { hkdf(mk, info: "cryptile/v1/thumb") }
    public static func searchKey(_ mk: Data) -> Data { hkdf(mk, info: "cryptile/v1/search") } // 1.1
    public static func shareKey(_ mk: Data) -> Data  { hkdf(mk, info: "cryptile/v1/share") }  // 1.2
}

// MARK: - Padding (ISO/IEC 7816-4 to a bucket boundary)

public enum Padding {
    public static func pad(_ data: Data, bucket: Int = Cryptile.padBucket) -> Data {
        let n = data.count + 1
        let total = ((n + bucket - 1) / bucket) * bucket
        return data + Data([0x80]) + Data(count: total - n)
    }

    public static func unpad(_ data: Data) throws -> Data {
        let data = Data(data)
        var end = data.count
        while end > 0 && data[data.startIndex + end - 1] == 0 { end -= 1 }
        guard end > 0, data[data.startIndex + end - 1] == 0x80 else { throw CryptileError.badPadding }
        return data.prefix(end - 1)
    }
}

// MARK: - Blobs

public enum Blob {
    /// Small-blob format: header(6) || nonce(12) || AES-256-GCM(pad(plaintext), aad: header)
    public static func seal(key: Data, type: Cryptile.BlobType, plaintext: Data,
                            nonce: Data? = nil) throws -> Data {
        let h = Cryptile.header(type)
        let n = try nonce.map { try AES.GCM.Nonce(data: $0) } ?? AES.GCM.Nonce()
        let box = try AES.GCM.seal(Padding.pad(plaintext), using: SymmetricKey(data: key),
                                   nonce: n, authenticating: h)
        return h + Data(n) + box.ciphertext + box.tag
    }

    public static func open(key: Data, blob: Data) throws -> (Cryptile.BlobType, Data) {
        let blob = Data(blob)   // rebase: slices may not start at 0
        guard blob.count >= 6 + 12 + 16 else { throw CryptileError.badFormat("short blob") }
        let h = blob.prefix(6)
        guard h.prefix(4) == Cryptile.magic, h[h.startIndex + 4] == Cryptile.version,
              let t = Cryptile.BlobType(rawValue: h[h.startIndex + 5]) else { throw CryptileError.badFormat("header") }
        let nonce = blob.subdata(in: 6..<18)
        let body = blob.suffix(from: 18)
        let ct = body.prefix(body.count - 16), tag = body.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
        guard let pt = try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: h) else {
            throw CryptileError.authenticationFailed
        }
        return (t, try Padding.unpad(pt))
    }

    /// Large-file STREAM construction.
    /// Layout: header(6) || fileNonce(8) || [ u32be(len) || ct ]*
    /// chunk i: nonce = fileNonce || u32be(i); aad = header || u32be(i) || last(1).
    /// Only the final chunk is padded. Truncation and reordering fail authentication.
    public static func sealFile(key: Data, plaintext: Data, fileNonce: Data? = nil) throws -> Data {
        let h = Cryptile.header(.file)
        let fn = fileNonce ?? Data.random(8)
        precondition(fn.count == 8)
        var out = h + fn
        let k = SymmetricKey(data: key)
        let count = max(1, (plaintext.count + Cryptile.chunk - 1) / Cryptile.chunk)
        for i in 0..<count {
            let lo = i * Cryptile.chunk, hi = min(plaintext.count, lo + Cryptile.chunk)
            let piece = plaintext.count == 0 ? Data() : plaintext.subdata(in: lo..<hi)
            let last = i == count - 1
            let nonce = try AES.GCM.Nonce(data: fn + UInt32(i).be)
            let aad = h + UInt32(i).be + Data([last ? 1 : 0])
            let box = try AES.GCM.seal(last ? Padding.pad(piece) : piece, using: k, nonce: nonce, authenticating: aad)
            let ct = box.ciphertext + box.tag
            out += UInt32(ct.count).be + ct
        }
        return out
    }

    public static func openFile(key: Data, blob: Data) throws -> Data {
        let blob = Data(blob)
        guard blob.count >= 14 else { throw CryptileError.badFormat("short file") }
        let h = blob.prefix(6)
        guard h.prefix(4) == Cryptile.magic, h[h.startIndex + 4] == Cryptile.version,
              h[h.startIndex + 5] == Cryptile.BlobType.file.rawValue else { throw CryptileError.badFormat("file header") }
        let fn = blob.subdata(in: 6..<14)
        let k = SymmetricKey(data: key)
        var pos = 14, i: UInt32 = 0
        var out = Data()
        while pos < blob.count {
            guard pos + 4 <= blob.count else { throw CryptileError.badFormat("chunk length") }
            let n = Int(UInt32(be: blob.subdata(in: pos..<pos + 4))); pos += 4
            guard n >= 16, pos + n <= blob.count else { throw CryptileError.badFormat("chunk") }
            let ct = blob.subdata(in: pos..<pos + n); pos += n
            let last = pos >= blob.count
            let aad = h + i.be + Data([last ? 1 : 0])
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: fn + i.be),
                                            ciphertext: ct.prefix(n - 16), tag: ct.suffix(16))
            guard let pt = try? AES.GCM.open(box, using: k, authenticating: aad) else {
                throw CryptileError.authenticationFailed
            }
            out += last ? try Padding.unpad(pt) : pt
            i += 1
        }
        return out
    }
}

// MARK: - Key wrap

enum KeyWrap {
    static let aad = Data("cryptile/v1/mk".utf8)

    /// nonce(12) || AES-GCM(mk, aad "cryptile/v1/mk") -> 60 bytes
    static func wrap(mk: Data, under key: Data, nonce: Data? = nil) throws -> Data {
        let n = try nonce.map { try AES.GCM.Nonce(data: $0) } ?? AES.GCM.Nonce()
        let box = try AES.GCM.seal(mk, using: SymmetricKey(data: key), nonce: n, authenticating: aad)
        return Data(n) + box.ciphertext + box.tag
    }

    static func unwrap(_ wrapped: Data, under key: Data) throws -> Data {
        let wrapped = Data(wrapped)
        guard wrapped.count == 60 else { throw CryptileError.badFormat("wrapped mk") }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: wrapped.prefix(12)),
                                        ciphertext: wrapped.subdata(in: 12..<44), tag: wrapped.suffix(16))
        guard let mk = try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad) else {
            throw CryptileError.authenticationFailed
        }
        return mk
    }
}

// MARK: - Recovery phrase (9 BIP39 words = 96 bits entropy + 3-bit checksum)

public enum RecoveryPhrase {
    public static func generate() -> (rk: Data, phrase: String) {
        let rk = Data.random(12)
        return (rk, phrase(from: rk))
    }

    public static func phrase(from rk: Data) -> String {
        precondition(rk.count == 12)
        let check = Data(SHA256.hash(data: rk))[0]
        var bits = rk.flatMap { b in (0..<8).reversed().map { (b >> $0) & 1 } }
        bits += (0..<3).reversed().map { (check >> (5 + $0)) & 1 }   // top 3 bits of SHA-256(rk)[0]
        var words: [String] = []
        for w in 0..<9 {
            var idx = 0
            for b in bits[w * 11..<(w + 1) * 11] { idx = (idx << 1) | Int(b) }
            words.append(BIP39.words[idx])
        }
        return words.joined(separator: " ")
    }

    public static func recoveryEntropy(from phrase: String) throws -> Data {
        let words = phrase.lowercased().split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)
        guard words.count == 9 else { throw CryptileError.badRecoveryPhrase("need 9 words") }
        var bits: [UInt8] = []
        for w in words {
            guard let i = BIP39.index[w] else { throw CryptileError.badRecoveryPhrase("unknown word '\(w)'") }
            bits += (0..<11).reversed().map { UInt8((i >> $0) & 1) }
        }
        var rk = Data(count: 12)
        for i in 0..<96 where bits[i] == 1 { rk[i / 8] |= 1 << (7 - UInt8(i % 8)) }
        let check = Data(SHA256.hash(data: rk))[0]
        let expect = (0..<3).reversed().map { (check >> (5 + $0)) & 1 }
        guard Array(bits[96..<99]) == expect else { throw CryptileError.badRecoveryPhrase("checksum") }
        return rk
    }

    /// K_recovery = HKDF-SHA256(rk, salt: recoverySalt(16), info: "cryptile/v1/recovery")
    public static func key(rk: Data, recoverySalt: Data) -> Data {
        KDF.hkdf(rk, info: "cryptile/v1/recovery", salt: recoverySalt)
    }
}

// MARK: - Vault index

public struct IndexEntry: Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var mime: String
    public var size: Int
    public var created: Int
    public var blob: String   // container filename of the file blob
    public var thumb: String  // container filename of the thumbnail blob
    /// Optional folder name inside the vault (omitted from the JSON when nil, so the canonical
    /// encoding of folder-less entries is unchanged and the vectors still hold).
    public var folder: String?
    /// Favourite flag (omitted when nil).
    public var favorite: Bool?
    /// Text recognised on-device at import (photos via Vision, PDFs via PDFKit), kept here so it
    /// is encrypted with the index and searchable without ever leaving the device. Omitted when nil.
    public var text: String?
    /// Where and when the photo or video was taken, read from its own metadata at import and
    /// kept only here, inside the encrypted index. Omitted when the file carries none.
    public var lat: Double?
    public var lon: Double?
    public var taken: Int?
    public init(id: String, name: String, mime: String, size: Int, created: Int, blob: String, thumb: String,
                folder: String? = nil, favorite: Bool? = nil, text: String? = nil,
                lat: Double? = nil, lon: Double? = nil, taken: Int? = nil) {
        self.id = id; self.name = name; self.mime = mime; self.size = size
        self.created = created; self.blob = blob; self.thumb = thumb; self.folder = folder
        self.favorite = favorite; self.text = text; self.lat = lat; self.lon = lon; self.taken = taken
    }
    /// Capture time when known, otherwise the import time. Date sorting uses this.
    public var when: Int { taken ?? created }
}

/// The decrypted index document. `mk_recovery` lets the recovery phrase alone open the vault
/// on a new device (backup restore) — no device salt or pattern needed.
public struct IndexDocument: Codable, Equatable, Sendable {
    public var v: Int
    public var recovery_salt: String
    public var mk_recovery: String
    public var entries: [IndexEntry]
    /// Folder names that exist in this vault, including empty ones. Omitted when nil, so the
    /// canonical encoding (and the vectors) are unchanged for documents without folders.
    public var folders: [String]?
    /// Hex of the 12-byte recovery entropy, kept inside the pattern-sealed index so the app can
    /// re-seal the recovery slot on every change and show the phrase on demand. Anyone holding
    /// the pattern already holds the vault, so this adds no exposure. Omitted when nil.
    public var rk: String?
}

// MARK: - Recovery slot

/// A second, index-shaped blob per vault that the recovery phrase alone can open (no pattern,
/// no device salt), so a backup can be restored on a new device. Named and keyed from RK only.
///   K_slot    = HKDF(RK, "cryptile/v1/recovery-slot")
///   slot name = hex(HMAC-SHA256(HKDF(RK, "cryptile/v1/recovery-lookup"), "cryptile/v1/recovery-name"))[:32]
///   blob      = seal(K_slot, INDEX, MK(32) || indexJSON)
public enum RecoverySlot {
    public static func key(rk: Data) -> Data { KDF.hkdf(rk, info: "cryptile/v1/recovery-slot") }

    public static func name(rk: Data) -> String {
        let lookup = KDF.hkdf(rk, info: "cryptile/v1/recovery-lookup")
        let mac = HMAC<SHA256>.authenticationCode(for: Data("cryptile/v1/recovery-name".utf8), using: SymmetricKey(data: lookup))
        return String(Data(mac).hex.prefix(32))
    }

    public static func build(rk: Data, masterKey mk: Data, document: IndexDocument, nonce: Data? = nil) throws -> Data {
        try Blob.seal(key: key(rk: rk), type: .index, plaintext: mk + VaultIndex.encode(document), nonce: nonce)
    }

    public static func open(rk: Data, blob: Data) throws -> OpenedVault {
        let (t, body) = try Blob.open(key: key(rk: rk), blob: blob)
        guard t == .index, body.count > 32 else { throw CryptileError.badFormat("recovery slot") }
        let b = Data(body)
        let doc = try JSONDecoder().decode(IndexDocument.self, from: b.suffix(from: 32))
        return OpenedVault(masterKey: b.prefix(32), document: doc)
    }
}

public struct OpenedVault: Sendable {
    public let masterKey: Data
    public let document: IndexDocument
}

public enum VaultIndex {
    /// JSON encoding must match Python `json.dumps(sort_keys=True, separators=(',',':'))`:
    /// sorted keys, no whitespace, forward slashes unescaped.
    static func encode(_ doc: IndexDocument) throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try e.encode(doc)
    }

    /// Index blob = Blob.seal(K_wrap, .index,  wrappedMK(60) || indexJSON)
    public static func build(patternKey pk: Data, masterKey mk: Data, entries: [IndexEntry],
                             recoveryEntropy rk: Data, recoverySalt: Data,
                             nonces: (mk: Data?, rec: Data?, index: Data?) = (nil, nil, nil)) throws -> Data {
        let kWrap = KDF.wrapKey(pk)
        let mkWrapped = try KeyWrap.wrap(mk: mk, under: kWrap, nonce: nonces.mk)
        let kRec = RecoveryPhrase.key(rk: rk, recoverySalt: recoverySalt)
        let mkRec = try KeyWrap.wrap(mk: mk, under: kRec, nonce: nonces.rec)
        let doc = IndexDocument(v: Int(Cryptile.version), recovery_salt: recoverySalt.hex,
                                mk_recovery: mkRec.hex, entries: entries)
        return try Blob.seal(key: kWrap, type: .index, plaintext: mkWrapped + encode(doc), nonce: nonces.index)
    }

    /// Re-seal an already-open vault's index with a new entry list. The recovery wrap in the
    /// document is carried over untouched, so the recovery phrase is not needed after creation.
    public static func rebuild(patternKey pk: Data, masterKey mk: Data, document: IndexDocument,
                               entries: [IndexEntry]) throws -> Data {
        let kWrap = KDF.wrapKey(pk)
        let mkWrapped = try KeyWrap.wrap(mk: mk, under: kWrap)
        var doc = document
        doc.entries = entries
        return try Blob.seal(key: kWrap, type: .index, plaintext: mkWrapped + encode(doc))
    }

    public static func open(patternKey pk: Data, blob: Data) throws -> OpenedVault {
        let kWrap = KDF.wrapKey(pk)
        let (t, body) = try Blob.open(key: kWrap, blob: blob)
        guard t == .index, body.count > 60 else { throw CryptileError.badFormat("index body") }
        let b = Data(body)
        let mk = try KeyWrap.unwrap(b.prefix(60), under: kWrap)
        let doc = try JSONDecoder().decode(IndexDocument.self, from: b.suffix(from: 60))
        return OpenedVault(masterKey: mk, document: doc)
    }

    /// Restore path: the phrase alone yields MK from an index document's recovery wrap.
    /// On restore the app tries this against every index-shaped slot; auth failure = not ours.
    public static func masterKey(fromPhrase phrase: String, document: IndexDocument) throws -> Data {
        let rk = try RecoveryPhrase.recoveryEntropy(from: phrase)
        let kRec = RecoveryPhrase.key(rk: rk, recoverySalt: Data(hex: document.recovery_salt))
        return try KeyWrap.unwrap(Data(hex: document.mk_recovery), under: kRec)
    }
}

// MARK: - Container shape (decoy slots)

/// Vaultaire's acknowledged leak: an examiner can count index files = number of vaults.
/// Cryptile keeps the count uninformative: the container always holds >= minIndexSlots
/// index-shaped blobs, real + random decoys, and decoys are re-randomized on every write.
public enum ContainerShape {
    public static func totalIndexSlots(real: Int) -> Int {
        max(Cryptile.minIndexSlots, real * 2)
    }

    /// Random bytes shaped like an index blob of a plausible bucketed size. The header says
    /// `.index` on purpose: a decoy that announced itself in its plaintext type byte would be
    /// no decoy at all. (`BlobType.decoy` is reserved for app-level bookkeeping blobs.)
    public static func decoyBlob() -> Data {
        let buckets = Int.random(in: 1...4)
        return Cryptile.header(.index) + Data.random(12 + buckets * Cryptile.padBucket + 16)
    }

    /// Decoy filenames are indistinguishable from real slot names (32 hex chars).
    public static func decoySlotName() -> String { Data.random(16).hex }
}

// MARK: - Small helpers

extension Data {
    public var hex: String { map { String(format: "%02x", $0) }.joined() }

    public init(hex: String) {
        var d = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            d.append(UInt8(hex[i..<j], radix: 16) ?? 0)
            i = j
        }
        self = d
    }

    public static func random(_ n: Int) -> Data {
        var d = Data(count: n)
        let ok = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        precondition(ok == errSecSuccess)
        return d
    }
}

extension UInt32 {
    var be: Data { withUnsafeBytes(of: bigEndian) { Data($0) } }
    init(be data: Data) {
        precondition(data.count == 4)
        self = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
    }
}
