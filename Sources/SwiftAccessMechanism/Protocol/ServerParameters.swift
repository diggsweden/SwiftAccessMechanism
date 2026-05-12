// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

import Foundation
import Security

/// Server configuration for Protocol layer.
///
/// Encapsulates the server's JWS public key (for device-mode ECDH-ES encryption and JWS
/// verification) and OPAQUE parameters (context + server identifier).
///
/// `ServerParameters` is `Codable` — persist it after calling `new_state` and restore it
/// on subsequent launches so the client uses the correct server-derived keys and identifiers.
///
/// ## Example
///
/// ```swift
/// // First launch: start with static defaults, then update from server
/// var params = try ServerParameters()
/// let (client, identity) = try await BFFHttpClient.createClient(baseUrl: url, serverParameters: params)
/// persist(client.serverParameters)   // save updated params
/// persist(identity.toClientIdentity())
///
/// // Subsequent launches: restore persisted params
/// let params = load(ServerParameters.self)
/// let client = try BFFHttpClient(identity: BFFIdentity(from: storedIdentity),
///                                serverParameters: params, baseUrl: url)
/// ```
public struct ServerParameters: Codable {
    /// Server's P-256 public key in JWK format (for ECDH-ES encryption and JWS verification).
    public let serverJwsPublicKey: JwkKey

    /// OPAQUE protocol context (arbitrary application-specific data).
    public let opaqueContext: Data

    /// OPAQUE server identifier (returned by server in `new_state` response).
    public let opaqueServerIdentifier: Data

    /// Derived `SecKey` — not encoded, computed from `serverJwsPublicKey` at init.
    private let _serverPublicKey: SecKey

    /// Server's P-256 public key as `SecKey` (backward-compat accessor).
    public var serverPublicKey: SecKey { _serverPublicKey }

    enum CodingKeys: CodingKey {
        case serverJwsPublicKey, opaqueContext, opaqueServerIdentifier
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let jwk = try c.decode(JwkKey.self, forKey: .serverJwsPublicKey)
        self.serverJwsPublicKey = jwk
        self.opaqueContext = try c.decode(Data.self, forKey: .opaqueContext)
        self.opaqueServerIdentifier = try c.decode(Data.self, forKey: .opaqueServerIdentifier)
        self._serverPublicKey = try jwk.toSecKey()
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serverJwsPublicKey, forKey: .serverJwsPublicKey)
        try c.encode(opaqueContext, forKey: .opaqueContext)
        try c.encode(opaqueServerIdentifier, forKey: .opaqueServerIdentifier)
    }

    // MARK: - Internal designated init

    init(serverJwsPublicKey: JwkKey, opaqueContext: Data, opaqueServerIdentifier: Data) throws {
        self.serverJwsPublicKey = serverJwsPublicKey
        self.opaqueContext = opaqueContext
        self.opaqueServerIdentifier = opaqueServerIdentifier
        self._serverPublicKey = try serverJwsPublicKey.toSecKey()
    }

    // MARK: - Public inits

    /// Default test/dev server public key PEM.
    private static let defaultServerPublicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpzQxuXLeiPyzitMKQbUSVOD3Axb+
    l9LqVjs5GnYanA1k4AmMUToWpITw5XXM48NPhbgMhoM0FUp4OQ26z/vCQQ==
    -----END PUBLIC KEY-----
    """

    /// Initializes with test/dev defaults.
    public init(serverIdentifier: Data = Data("cloud-wallet.digg.se".utf8)) throws {
        try self.init(serverPublicKeyPEM: Self.defaultServerPublicKeyPEM,
                      opaqueContext: Data("RPS-Ops".utf8),
                      opaqueServerIdentifier: serverIdentifier)
    }

    /// Initializes with a PEM-encoded server public key and explicit OPAQUE parameters.
    ///
    /// - Parameters:
    ///   - serverPublicKeyPEM: Server's P-256 public key in PEM format (BEGIN PUBLIC KEY).
    ///   - opaqueContext: OPAQUE context (arbitrary application data, default: "RPS-Ops").
    ///   - opaqueServerIdentifier: OPAQUE server identifier (default: "cloud-wallet.digg.se").
    /// - Throws: If PEM parsing fails.
    public init(
        serverPublicKeyPEM: String,
        opaqueContext: Data = Data("RPS-Ops".utf8),
        opaqueServerIdentifier: Data = Data("cloud-wallet.digg.se".utf8)
    ) throws {
        let secKey = try parseKey(serverPublicKeyPEM)
        let jwk = try JwkKey.from(publicKey: secKey)
        try self.init(serverJwsPublicKey: jwk, opaqueContext: opaqueContext, opaqueServerIdentifier: opaqueServerIdentifier)
    }
}
