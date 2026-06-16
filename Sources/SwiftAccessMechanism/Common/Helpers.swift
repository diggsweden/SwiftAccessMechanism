// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

import Foundation
import CryptoKit
import Security
import JOSESwift

/// Errors from ``parseKey(_:_:_:)`` operations.
enum ParseKeyError: Error {
    case clientKeyParseError
    case serverKeyParseError
    case keyParseError
    case encodingError
}

/// Key encoding format for ``parseKey(_:_:_:)``.
enum keyEncoding {
    case pemEncoded, derEncoded
}

/// Key class (public or private) for ``parseKey(_:_:_:)``.
enum keyClass {
    case publicKey, privateKey
}

/// Convenience: parse a PEM-encoded public key string into a `SecKey`.
func parseKey(_ pemString: String) throws -> SecKey {
    guard let key = pemString.data(using: .ascii) else {
        throw ParseKeyError.encodingError
    }

    return try parseKey(key, .pemEncoded, .publicKey)
}

/// Parse a PEM/DER-encoded EC P-256 key (either private or public) and return a SecKey
func parseKey(_ key: Data, _ encoding: keyEncoding, _ keyClass: keyClass) throws -> SecKey {
    // Helper function to create SecKey from x963 data
    func createSecKey(from x963Data: Data, keyClass: CFString, error: Error) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: keyClass,
            kSecAttrKeySizeInBits as String: 256
        ]

        var cfError: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(x963Data as CFData, attributes as CFDictionary, &cfError) else {
            throw error
        }
        return secKey
    }

    switch encoding {
    case .pemEncoded:
        guard let pemString = String(data: key, encoding: .ascii) else {
            throw ParseKeyError.keyParseError
        }

        switch keyClass {
        case .privateKey:
            if let privateKey = try? P256.Signing.PrivateKey(pemRepresentation: pemString) {
                return try createSecKey(from: privateKey.x963Representation,
                                        keyClass: kSecAttrKeyClassPrivate,
                                        error: ParseKeyError.clientKeyParseError)
            }
        case .publicKey:
            if let publicKey = try? P256.Signing.PublicKey(pemRepresentation: pemString) {
                return try createSecKey(from: publicKey.x963Representation,
                                        keyClass: kSecAttrKeyClassPublic,
                                        error: ParseKeyError.serverKeyParseError)
            }
        }
    case .derEncoded:
        switch keyClass {
        case .privateKey:
            if let privateKey = try? P256.Signing.PrivateKey(derRepresentation: key) {
                return try createSecKey(from: privateKey.x963Representation,
                                        keyClass: kSecAttrKeyClassPrivate,
                                        error: ParseKeyError.clientKeyParseError)
            }
        case .publicKey:
            // Try to parse as public key
            if let publicKey = try? P256.Signing.PublicKey(derRepresentation: key) {
                return try createSecKey(from: publicKey.x963Representation,
                                        keyClass: kSecAttrKeyClassPublic,
                                        error: ParseKeyError.serverKeyParseError)
            }
        }
    }

    // If neither worked, throw an error
    throw ParseKeyError.clientKeyParseError
}

/// Errors from ``computeJwkThumbprint(publicKey:)``.
enum JwkThumbprintError: Error {
    /// Failed to decode base64url thumbprint.
    case base64DecodeFailed
}

/// Compute JWK thumbprint (RFC 7638) for a P-256 public key.
///
/// Uses JOSESwift's built-in thumbprint calculation. Returns SHA-256 hash
/// of the JWK canonical form as base64url string.
/// Standard OPAQUE client identifier per RFC 7638.
///
/// - Parameter publicKey: P-256 public key (SecKey).
/// - Returns: JWK thumbprint in base64url format
/// - Throws: Key conversion errors or ``JwkThumbprintError``.
func computeJwkThumbprint(publicKey: SecKey) throws -> String {
    let ecPublicKey = try ECPublicKey(publicKey: publicKey)
    return try ecPublicKey.thumbprint(algorithm: .SHA256)
}

/// Compute JWK thumbprint (RFC 7638) from a P-256 private key.
///
/// Extracts public key from private key, then computes thumbprint.
///
/// - Parameter privateKey: P-256 private key (SecKey).
/// - Returns: JWK thumbprint in base64url format
/// - Throws: Key conversion errors or ``JwkThumbprintError``.
func computeJwkThumbprint(privateKey: SecKey) throws -> String {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw ParseKeyError.keyParseError
    }
    return try computeJwkThumbprint(publicKey: publicKey)
}
