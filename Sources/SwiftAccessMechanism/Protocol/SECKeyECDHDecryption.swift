// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

// SECKeyECDHDecryption.swift
// SE-compatible fallback for device-mode JWE decryption.
//
// TODO: Remove this file once JOSESwift supports Secure Enclave keys natively.
//       Track upstream: https://github.com/airsidemobile/JOSESwift/pull/460
//       When that (or equivalent) is merged, ECPrivateKey(privateKey:) will stop
//       failing for SE keys and the JOSESwift path in decryptDeviceJWE() will
//       always succeed — making this entire file redundant.
//
// Background: JOSESwift's ECPrivateKey(privateKey:) calls
// SecKeyCopyExternalRepresentation, which fails for Secure Enclave keys.
// The fallback below bypasses JOSESwift's Decrypter entirely: it parses the
// compact JWE manually, derives the CEK via SecKeyCopyKeyExchangeResult
// (SE-compatible) + Concat KDF (RFC 7518 §4.6.2), then decrypts with
// CryptoKit AES-256-GCM.

import Foundation
import Security
import JOSESwift
import CryptoKit

enum SECKeyECDHError: Error {
    case invalidCompactJWE
    case missingEPK
    case keyExchangeFailed(String)
    case unsupportedContentEncryption(String)
    case decryptionFailed(String)
}

/// SE-compatible ECDH-ES / A256GCM JWE decryption.
///
/// Called by Outer.swift when `session.decrypter` is nil (i.e. the client private key
/// is a Secure Enclave key and JOSESwift's `ECPrivateKey(privateKey:)` could not export it).
///
/// Parses the compact JWE manually, derives the CEK via `SecKeyCopyKeyExchangeResult`
/// (SE-compatible) + Concat KDF (RFC 7518 §4.6.2), then decrypts with CryptoKit AES-256-GCM.
///
/// - Parameters:
///   - privateKey: SE (or regular) P-256 private key — never exported.
///   - compactJWE: Compact serialization (`header.encKey.iv.ciphertext.tag`).
/// - Returns: Decrypted plaintext.
func decryptDeviceJWE(privateKey: SecKey, compactJWE: String) throws -> Data {
    let parts = compactJWE.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    guard parts.count == 5 else {
        throw SECKeyECDHError.invalidCompactJWE
    }

    // AAD = ASCII bytes of the base64url-encoded header (RFC 7516 §5.1 step 14)
    guard let aad = parts[0].data(using: .ascii) else {
        throw SECKeyECDHError.invalidCompactJWE
    }

    // Use JOSESwift only to parse the header (epk / apu / apv live there)
    let jwe = try JWE(compactSerialization: compactJWE)
    let cek = try ecdhCEK(privateKey: privateKey, header: jwe.header, encryption: .A256GCM)

    // parts[1] = encrypted key — empty for ECDH-ES direct, ignored
    let iv         = decodeBase64URL(parts[2])
    let ciphertext = decodeBase64URL(parts[3])
    let tag        = decodeBase64URL(parts[4])

    // AES-256-GCM decrypt with CryptoKit (qualify SymmetricKey to avoid JOSESwift clash)
    let symmetricKey = CryptoKit.SymmetricKey(data: cek)
    let nonce: AES.GCM.Nonce
    do {
        nonce = try AES.GCM.Nonce(data: iv)
    } catch {
        throw SECKeyECDHError.decryptionFailed("invalid IV length: \(iv.count), expected 12")
    }
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    do {
        return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
    } catch {
        throw SECKeyECDHError.decryptionFailed(error.localizedDescription)
    }
}

// MARK: - ECDH + Concat KDF ---------------------------------------------------

/// Derive the ECDH-ES CEK using a Secure Enclave private key.
///
/// Uses `SecKeyCopyKeyExchangeResult` (SE-compatible, no key export) then
/// runs Concat KDF per RFC 7518 §4.6.2.
private func ecdhCEK(privateKey: SecKey, header: JWEHeader, encryption: ContentEncryptionAlgorithm) throws -> Data {
    guard let epk = header.epk else {
        throw SECKeyECDHError.missingEPK
    }

    let epkSecKey = try epk.converted(to: SecKey.self)

    var cfError: Unmanaged<CFError>?
    guard let z = SecKeyCopyKeyExchangeResult(
        privateKey,
        .ecdhKeyExchangeStandard,
        epkSecKey,
        [:] as CFDictionary,
        &cfError
    ) as Data? else {
        let desc = cfError?.takeRetainedValue().localizedDescription ?? "unknown"
        throw SECKeyECDHError.keyExchangeFailed(desc)
    }

    let apu = decodeBase64URL(header.apu ?? "")
    let apv = decodeBase64URL(header.apv ?? "")
    return try ecdhConcatKDF(z: z, encryption: encryption, apu: apu, apv: apv)
}

// MARK: - Concat KDF (RFC 7518 §4.6.2 / NIST SP 800-56A §5.8.1) --------------

private func ecdhConcatKDF(z: Data, encryption: ContentEncryptionAlgorithm, apu: Data, apv: Data) throws -> Data {
    guard let algIdData = encryption.rawValue.data(using: .utf8) else {
        throw SECKeyECDHError.unsupportedContentEncryption(encryption.rawValue)
    }
    let keyDataLenBits = try cekBitLength(for: encryption)

    let otherInfo = lengthPrefixed(algIdData)
        + lengthPrefixed(apu)
        + lengthPrefixed(apv)
        + bigEndian32(UInt32(keyDataLenBits))

    // One SHA-256 round covers ≤256-bit output; counter = 1
    let hashInput = bigEndian32(1) + z + otherInfo
    let digest = Data(SHA256.hash(data: hashInput))
    return digest.prefix((keyDataLenBits + 7) / 8)
}

private func cekBitLength(for enc: ContentEncryptionAlgorithm) throws -> Int {
    switch enc.rawValue {
    case "A128GCM":        return 128
    case "A192GCM":        return 192
    case "A256GCM":        return 256
    case "A128CBC-HS256":  return 256
    case "A192CBC-HS384":  return 384
    case "A256CBC-HS512":  return 512
    default:
        throw SECKeyECDHError.unsupportedContentEncryption(enc.rawValue)
    }
}

// MARK: - Helpers -------------------------------------------------------------

private func lengthPrefixed(_ data: Data) -> Data {
    bigEndian32(UInt32(data.count)) + data
}

private func bigEndian32(_ value: UInt32) -> Data {
    var v = value.bigEndian
    return Data(bytes: &v, count: 4)
}

func decodeBase64URL(_ string: String) -> Data {
    var s = string
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let pad = s.count % 4
    if pad != 0 { s += String(repeating: "=", count: 4 - pad) }
    return Data(base64Encoded: s) ?? Data()
}
