// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

////
////  PINStretch.swift
////  SwiftAccessMechanism
////
////  Created by Fredrik Thulin on 2025-11-20.
////

import Foundation
import CryptoKit
import OSLog


/// Errors thrown by ``PINStretch/stretch(input:)`` and related operations.
public enum PINStretchError: Error {
    /// Input data could not be encoded.
    case invalidPasswordEncoding
    /// Secure Enclave private key not available.
    case noEnclaveKey
    /// Encrypted data format is invalid.
    case invalidEncryptedData
    /// Decryption of stretched result failed.
    case decryptionFailed
    /// Catch-all for unexpected failures.
    case generalError
}

/// Stretches a weak PIN/password into a 32-byte key using Secure Enclave ECDH + HKDF.
///
/// ## Example
///
/// ```swift
/// let stretcher = PINStretch()
/// let password = try stretcher.stretch(input: "1234".data(using: .utf8)!)
/// // Use password with OPAQUE registration/authentication
/// ```
public struct PINStretch {

    fileprivate var enclave: AMSecureEnclave

    /// Creates a new PINStretch instance, loading or generating a Secure Enclave key.
    public init() {
        self.enclave = AMSecureEnclave()
    }

    /// Returns the Secure Enclave private key reference, or nil if unavailable.
    public var privateKeyRef: SecKey? {
        return enclave.privateKeyRef
    }

    /// Perform input stretching on raw input data and return a 32-byte derived key.
    ///
    /// "Stretching" is the term we use to explain that we increase the low bit-entropy value of e.g. a user's PIN
    /// with the high entropy value of an EC private key stored (and generated) in the devices secure enclave.
    ///
    /// This method implements the app's PIN-stretching primitive:
    /// 1. Maps the supplied `input` to an EC point on P-256 using `hashToCurveP256Sha256(...)`.
    ///    That function first performs a SHA-256 hashing internally.
    /// 2. Constructs an ephemeral P-256 private key from the h2c result and performs ECDH
    ///    with a private key stored in the Secure Enclave (via `AMSecureEnclave.privateKeyRef`).
    /// 3. The raw ECDH result is passed through HKDF(SHA-256) with explicit salt and info to
    ///    produce a uniformly-distributed 32-byte output which is returned.
    ///
    /// Important (cryptographic note):
    /// - The raw ECDH result is not uniformly distributed; applying HKDF(SHA-256)
    ///   is an essential step that removes potential bias and produces cryptographically
    ///   sound symmetric key material suitable for use as a 32-byte key or for further KDFs.
    /// - The Secure Enclave private key must be available; otherwise the function throws
    ///   `PINStretchError.noEnclaveKey`.
    ///
    /// - Parameter input: Raw input data to stretch (for example the user's PIN or password
    ///   encoded as UTF-8 data). The `hashToCurveP256Sha256` function will perform SHA-256
    ///   hashing internally, so callers should pass the raw input bytes.
    /// - Returns: A 32-byte derived key (Data) produced by HKDF(SHA-256) over the ECDH result.
    /// - Throws: One of `PINStretchError` on failure, or a system error if underlying crypto
    ///   operations (SecKey, CryptoKit) fail.
    public func stretch(input: Data) throws -> Data {
        guard let sePrivateKeyRef = self.enclave.privateKeyRef else {
            throw PINStretchError.noEnclaveKey
        }

        // Map input to curve point; hash is performed inside hashToCurveP256Sha256
        let domainSeparatorTag = "AccessMechanism.PIN-stretch.v1".data(using: .ascii)!
        let hashed2curve = try hashToCurveP256Sha256(input: input, dst: domainSeparatorTag)

        // If hashToCurve produced a compressed EC point (33 bytes, 0x02/0x03 prefix), strip the prefix
        var rawPoint = hashed2curve
        if rawPoint.count == 33, let first = rawPoint.first, first == 0x02 || first == 0x03 {
            rawPoint = Data(rawPoint.dropFirst())
        }

        // Validate we now have a 32-byte raw representation (raw P-256 point is always 32 bytes, secure enclave
        // only supports EC with NIST P-256 currently).
        guard rawPoint.count == 32 else {
            throw PINStretchError.generalError
        }

        let ephemeralPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawPoint)
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        // Convert to SecKey format for ECDH with Secure Enclave
        let ephemeralSecKey = try ephemeralPublicKey.secKey

        // Perform ECDH between ephemeral public key and Secure Enclave private key
        var error: Unmanaged<CFError>?
        let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandard

        guard let sharedSecret = SecKeyCopyKeyExchangeResult(
            sePrivateKeyRef,
            algorithm,
            ephemeralSecKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            if let error = error {
                throw error.takeRetainedValue() as Error
            }
            throw NSError(domain: "TestError", code: 2, userInfo: [NSLocalizedDescriptionKey: "ECDH failed"])
        }

        // Output of ECDH is not uniformly distributed. Pass through HKDF.
        let salt = Data("SwiftAccessMechanism.PINStretch".utf8)
        let info = Data("ECDH-Stretch".utf8)
        let stretchedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: info,
            outputByteCount: 32
        )

        var result: Data? = nil
        stretchedKey.withUnsafeBytes { result = Data($0) }

        guard let result else {
            throw PINStretchError.generalError
        }

        return result
    }
}

extension P256.KeyAgreement.PublicKey {
    var secKey: SecKey {
        get throws {
            let keyData = self.x963Representation
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 256
            ]

            guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil) else {
                throw CryptoKitError.invalidParameter
            }

            return secKey
        }
    }
}
