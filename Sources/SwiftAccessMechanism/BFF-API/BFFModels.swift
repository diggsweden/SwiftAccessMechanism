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
    let publicKey: JwkKey
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
    public let keyTag: String
    /// DEV-ONLY authorization code; required when registering a PIN.
    public let devAuthorizationCode: String?
}
