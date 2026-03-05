// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

import Foundation
import Security

/// Server configuration for Protocol layer.
///
/// Encapsulates server public key (for device-mode ECDH-ES encryption) and OPAQUE parameters (context + server identifier).
///
/// ## Example
///
/// ```swift
/// // Test/dev defaults
/// let params = try ServerParameters()
///
/// // Production config
/// let params = try ServerParameters(
///     serverPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n...",
///     opaqueContext: Data("EUDI-Wallet-Production".utf8),
///     opaqueServerIdentifier: Data("eudi.example.com".utf8)
/// )
/// ```
public struct ServerParameters {
    /// Server's P-256 public key for ECDH-ES encryption (device mode).
    let serverPublicKey: SecKey

    /// OPAQUE protocol context (arbitrary application-specific data).
    let opaqueContext: Data

    /// OPAQUE server identifier (typically server domain or service name).
    let opaqueServerIdentifier: Data

    /// Default test/dev server public key PEM
    private static let defaultServerPublicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpzQxuXLeiPyzitMKQbUSVOD3Axb+
    l9LqVjs5GnYanA1k4AmMUToWpITw5XXM48NPhbgMhoM0FUp4OQ26z/vCQQ==
    -----END PUBLIC KEY-----
    """

    /// Initializes with test/dev defaults.
    ///
    /// Uses built-in test server public key and default OPAQUE parameters.
    /// Suitable for development and integration testing.
    ///
    /// - Throws: If PEM parsing fails (should never happen with built-in key).
    public init(serverIdentifier: Data = Data("cloud-wallet.digg.se".utf8)) throws {
        try self.init(serverPublicKeyPEM: Self.defaultServerPublicKeyPEM, opaqueServerIdentifier: serverIdentifier)
    }

    /// Initializes with production server parameters.
    ///
    /// - Parameters:
    ///   - serverPublicKeyPEM: Server's P-256 public key in PEM format (BEGIN PUBLIC KEY).
    ///   - opaqueContext: OPAQUE context (arbitrary application data, default: "RPS-Ops").
    ///   - opaqueServerIdentifier: OPAQUE server identifier (default: "cloud-wallet.digg.se").
    ///
    /// - Throws: If PEM parsing fails (invalid format or key type).
    public init(
        serverPublicKeyPEM: String,
        opaqueContext: Data = Data("RPS-Ops".utf8),
        opaqueServerIdentifier: Data = Data("cloud-wallet.digg.se".utf8)
    ) throws {
        self.serverPublicKey = try parseKey(serverPublicKeyPEM)
        self.opaqueContext = opaqueContext
        self.opaqueServerIdentifier = opaqueServerIdentifier
    }
}
