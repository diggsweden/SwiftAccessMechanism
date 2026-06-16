// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  Models.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-12-03.
//
import Foundation
import Security
import JOSESwift


// MARK: - PAKE Structures

/// OPAQUE PAKE request payload.
///
/// Sent in ``InnerRequest`` data field for registration/authentication operations.
struct PakeRequest: Codable {
    let authorization: String?
    let purpose: String?
    let sessionDuration: Int?

    /// Base64-encoded OPAQUE message (KE1 or KE3).
    let requestData: String

    enum CodingKeys: String, CodingKey {
        case authorization, purpose
        case sessionDuration = "session_duration"
        case requestData = "data"
    }

    func serialize() throws -> Data {
        try JSONEncoder().encode(self)
    }

    static func deserialize(from data: Data) throws -> PakeRequest {
        try JSONDecoder().decode(PakeRequest.self, from: data)
    }
}

/// OPAQUE PAKE response payload.
///
/// Received in ``InnerResponse`` data field after registration/authentication operations.
///
/// ## Example
///
/// ```swift
/// let pakeResp: PakeResponse = try innerResponse.decodePayload(PakeResponse.self)
/// let credentialData = try pakeResp.decodedResponseData()
/// ```
public struct PakeResponse: Codable {
    /// Base64-encoded OPAQUE message (KE2) or session ID.
    public let responseData: String?

    enum CodingKeys: String, CodingKey {
        case responseData = "data"
    }

    enum Errors: Swift.Error {
        case payloadError
    }

    /// Decodes base64-encoded response data.
    ///
    /// - Returns: Raw OPAQUE message bytes.
    /// - Throws: ``Errors/payloadError`` if response data missing or invalid base64.
    func decodedResponseData() throws -> Data {
        guard let responseData = self.responseData,
              let data = Data(base64Encoded: responseData)
        else {
            throw Errors.payloadError
        }
        return data
    }

    /// Helper for debugging: attempt to decode `responseData` into raw bytes and
    /// return them as a UTF-8 string. Returns "nil" if decoding fails or the
    /// bytes are not valid UTF-8.
    func responseDataForDebug() -> String {
        do {
            let data = try decodedResponseData()
            if let s = String(data: data, encoding: .utf8) {
                return s
            }
            return "nil"
        } catch {
            return "nil"
        }
    }
}

// MARK: - HSM Structures

/// HSM key metadata.
///
/// Returned in ``HsmListResponse`` from HSM list keys operation.
public struct HsmKeyInfo: Codable {
    /// Key creation timestamp (ISO 8601 format).
    public let createdAt: String

    /// Public key (JWK format).
    public let publicKey: JwkKey

    /// Key ID (alias for `publicKey.kid`).
    public var kid: String? {
        publicKey.kid
    }

    enum CodingKeys: String, CodingKey {
        case createdAt = "created_at"
        case publicKey = "public_key"
    }
}

/// HSM list keys response.
///
/// ## Example
///
/// ```swift
/// let listResp: HsmListResponse = try innerResponse.decodePayload(HsmListResponse.self)
/// for keyInfo in listResp.keyInfo {
///     print("Key: \(keyInfo.kid)")
/// }
/// ```
public struct HsmListResponse: Codable {
    /// Array of key metadata.
    public let keyInfo: [HsmKeyInfo]

    enum CodingKeys: String, CodingKey {
        case keyInfo = "key_info"
    }
}

/// HSM create key response.
///
/// ## Example
///
/// ```swift
/// let createResp: HsmCreateKeyResponse = try innerResponse.decodePayload(HsmCreateKeyResponse.self)
/// let publicKey = try createResp.public_key.toSecKey()
/// ```
public struct HsmCreateKeyResponse: Codable {
    /// Generated key's public key (JWK format).
    public let public_key: JwkKey
}

/// HSM sign response.
///
/// ## Example
///
/// ```swift
/// let signResp: SignatureResponse = try innerResponse.decodePayload(SignatureResponse.self)
/// try verifySignature(publicKey: jwkKey, signature: signResp, digest: digest)
/// ```
public struct SignatureResponse: Codable {
    /// Base64-encoded DER signature.
    public let signature: String

    public enum Errors: Swift.Error {
        case payloadError
    }

    /// Decodes base64-encoded signature to DER bytes.
    ///
    /// - Returns: DER-encoded signature data.
    /// - Throws: ``Errors/payloadError`` if signature invalid base64.
    public func toDER() throws -> Data {
        guard let data = Data(base64Encoded: signature) else {
            throw Errors.payloadError
        }
        return data
    }
}

// MARK: - JWK

/// JWK EC public key representation.
///
/// Standard JSON Web Key format for P-256 elliptic curve keys.
///
/// ## Example
///
/// ```swift
/// let jwk = createKeyResponse.public_key
/// let secKey = try jwk.toSecKey()
/// // Use secKey for signature verification
/// ```
public struct JwkKey: Codable {
    /// Key type ("EC" for elliptic curve).
    public let kty: String

    /// Curve name ("P-256" / secp256r1).
    public let crv: String

    /// X coordinate (base64url-encoded).
    public let x: String

    /// Y coordinate (base64url-encoded).
    public let y: String

    /// Key ID (server-assigned identifier, optional).
    public let kid: String?

    enum CodingKeys: String, CodingKey {
        case kty, crv, x, y, kid
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(kty, forKey: .kty)
        try c.encode(crv, forKey: .crv)
        try c.encode(x, forKey: .x)
        try c.encode(y, forKey: .y)
        try c.encodeIfPresent(kid, forKey: .kid)
    }

    /// Converts JWK to `SecKey` for CryptoKit operations.
    ///
    /// - Returns: `SecKey` representation suitable for signature verification.
    /// - Throws: Conversion errors if JWK format invalid.
    public func toSecKey() throws -> SecKey {
        return try self.toECPublicKey().converted(to: SecKey.self)
    }

    func toECPublicKey() throws -> ECPublicKey {
        let data = try JSONEncoder().encode(self)
        return try ECPublicKey(data: data)
    }

    /// Creates `JwkKey` from a `SecKey` P-256 public key.
    ///
    /// - Parameter publicKey: P-256 public key (SecKey).
    /// - Returns: `JwkKey` with `kid` set to JWK thumbprint (RFC 7638).
    /// - Throws: Key conversion errors.
    public static func from(publicKey: SecKey) throws -> JwkKey {
        let ecPublicKey = try ECPublicKey(publicKey: publicKey)
        let kid = try ecPublicKey.thumbprint(algorithm: .SHA256)
        return JwkKey(kty: "EC", crv: ecPublicKey.crv.rawValue, x: ecPublicKey.x, y: ecPublicKey.y, kid: kid)
    }
}
