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
public struct HSMRequest: Codable, Sendable {
    // Client identifier
    public let clientId: String?
    // Compact JWS string containing the signed OuterRequest
    public let outerRequestJws: String

    public init(clientId: String? = nil, outerRequestJws: String) {
        self.clientId = clientId
        self.outerRequestJws = outerRequestJws
    }
}

// MARK: - device-states endpoint

/// Request body for `POST /hsm/v1/device-states`.
struct NewStateRequest: Codable {
    let publicKey: JwkKey
    let clientId: String?
    let overwrite: Bool
    let ttl: String?

    enum CodingKeys: String, CodingKey {
        case publicKey
        case clientId = "client_id"
        case overwrite, ttl
    }
}

/// Response body from `POST /hsm/v1/device-states`.
public struct NewStateResponse: Codable {
    public let status: InnerResponse.Status
    /// Server-assigned (or echoed) client identifier.
    public let clientId: String?
    public let devAuthorizationCode: String?
    /// Server's current JWS public key; use for device-mode JWE encryption if present.
    let serverJwsPublicKey: JwkKey?
    /// OPAQUE server identifier returned by server; use in register/authenticate finish operations.
    let opaqueServerId: String?
}

// MARK: - Client Identity

/// Persisted client identity — store across app launches (e.g. UserDefaults via JSONEncoder).
///
/// Created by ``BFFHttpClient/createClient(baseUrl:serverParameters:ttl:)``.
/// Restored via ``BFFHttpClient/resume(transport:clientId:privateKey:serverParameters:)``.
public struct ClientIdentity: Codable {
    /// Server-assigned client UUID.
    public let clientId: String
    /// Keychain `applicationTag` for the device's SE private key.
    public let keyTag: String
    /// DEV-ONLY authorization code; required when registering a PIN.
    public let devAuthorizationCode: String?
}
