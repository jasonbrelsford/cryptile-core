import Foundation
import CryptoKit
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// PBKDF2-HMAC-SHA512. On Apple platforms the CommonCrypto implementation is used
/// (hardware-accelerated SHA-512, ~10x faster than a Swift loop). `pure` is the
/// readable, auditable version and the test suite asserts the two agree.
public enum PBKDF2 {
    public static func sha512(password: Data, salt: Data, iterations: Int, length: Int) -> Data {
        #if canImport(CommonCrypto)
        var out = Data(count: length)
        let rc = out.withUnsafeMutableBytes { outPtr in
            password.withUnsafeBytes { pwPtr in
                salt.withUnsafeBytes { saltPtr in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         pwPtr.baseAddress?.assumingMemoryBound(to: Int8.self), password.count,
                                         saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                                         UInt32(iterations),
                                         outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), length)
                }
            }
        }
        precondition(rc == kCCSuccess, "CCKeyDerivationPBKDF failed: \(rc)")
        return out
        #else
        return pure(password: password, salt: salt, iterations: iterations, length: length)
        #endif
    }

    /// RFC 8018 §5.2, written out so an auditor can read it in one screen.
    public static func pure(password: Data, salt: Data, iterations: Int, length: Int) -> Data {
        let key = SymmetricKey(data: password)
        let hLen = 64
        let blocks = (length + hLen - 1) / hLen
        var out = Data()
        for i in 1...blocks {
            var u = Data(HMAC<SHA512>.authenticationCode(for: salt + UInt32(i).be, using: key))
            var t = u
            if iterations > 1 {
                for _ in 2...iterations {
                    u = Data(HMAC<SHA512>.authenticationCode(for: u, using: key))
                    for j in 0..<hLen { t[j] ^= u[j] }
                }
            }
            out += t
        }
        return out.prefix(length)
    }
}
