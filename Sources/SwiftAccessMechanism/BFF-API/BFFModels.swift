// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  BFFModels.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-12-03.
//
import Foundation


// MARK: - API Request Structure
struct BFFRequest: Codable {
    // Client identifier
    let clientId: String
    // Compact JWS string containing the signed OuterRequest
    let outerRequestJws: String
}

// MARK: - device-states endpoint

/// Request body for `POST /hsm/v1/device-states`.
struct NewStateRequest: Codable {
    let clientJwsPublicKey: JwkKey
    let clientJwePublicKey: JwkKey?
    let clientId: String?
    let overwrite: Bool
    let ttl: String?
}

/// Response body from `POST /hsm/v1/device-states`.
public struct NewStateResponse: Codable {
    public let status: String
    /// Server-assigned (or echoed) client identifier.
    public let clientId: String?
    /// DEV-ONLY authorization code; required for PIN registration.
    public let devAuthorizationCode: String?
    /// Server's current JWS public key; use for device-mode JWE encryption if present.
    let serverJwsPublicKey: JwkKey?
    let serverJwePublicKey: JwkKey?
    /// OPAQUE server identifier returned by server; use in register/authenticate finish operations.
    let opaqueServerId: String?
}

// MARK: - Client Identity

/// Persisted client identity — store across app launches (e.g. UserDefaults via JSONEncoder).
///
/// Created by ``BFFHttpClient/createClient(baseUrl:serverParameters:ttl:)``.
/// Restored via ``BFFHttpClient/loadClient(baseUrl:identity:serverParameters:)``.
public struct ClientIdentity: Codable {
    /// Server-assigned client UUID.
    public let clientId: String
    /// Keychain `applicationTag` for the device's SE private key.
    public let jwsKeyTag: String
    public let jweKeyTag: String
    /// DEV-ONLY authorization code; required when registering a PIN.
    public let devAuthorizationCode: String?

    public init(clientId: String, jwsKeyTag: String, jweKeyTag: String, devAuthorizationCode: String?) {
        self.clientId = clientId
        self.jwsKeyTag = jwsKeyTag
        self.jweKeyTag = jweKeyTag
        self.devAuthorizationCode = devAuthorizationCode
    }

    enum CodingKeys: String, CodingKey {
        case clientId, jweKeyTag, devAuthorizationCode
        case jwsKeyTag
        case legacyKeyTag = "keyTag"  // pre-key-separation fallback
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.clientId = try c.decode(String.self, forKey: .clientId)
        // Accept old "keyTag" (pre-key-separation) as fallback for jwsKeyTag.
        let jwsTag = try c.decodeIfPresent(String.self, forKey: .jwsKeyTag)
            ?? c.decode(String.self, forKey: .legacyKeyTag)
        self.jwsKeyTag = jwsTag
        self.jweKeyTag = try c.decodeIfPresent(String.self, forKey: .jweKeyTag) ?? jwsTag
        self.devAuthorizationCode = try c.decodeIfPresent(String.self, forKey: .devAuthorizationCode)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(clientId, forKey: .clientId)
        try c.encode(jwsKeyTag, forKey: .jwsKeyTag)
        try c.encode(jweKeyTag, forKey: .jweKeyTag)
        try c.encodeIfPresent(devAuthorizationCode, forKey: .devAuthorizationCode)
    }
}
