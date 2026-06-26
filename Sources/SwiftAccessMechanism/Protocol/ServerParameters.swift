// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

import Foundation
import Security

/// Server configuration for Protocol layer.
///
/// Encapsulates the server's JWS and JWE public keys (for device-mode ECDH-ES encryption and JWS
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

    /// Server's JWE P-256 public key; equal to `serverJwsPublicKey` on single-key servers.
    public let serverJwePublicKey: JwkKey

    /// OPAQUE protocol context (arbitrary application-specific data).
    public let opaqueContext: Data

    /// OPAQUE server identifier (returned by server in `new_state` response).
    public let opaqueServerIdentifier: Data

    /// Derived `SecKey` — not encoded, computed from `serverJwsPublicKey` at init.
    private let _serverJwsSecKey: SecKey
    private let _serverJweSecKey: SecKey

    /// Server's P-256 public key as `SecKey` (backward-compat accessor).
    public var serverPublicKey: SecKey { _serverJwsSecKey }
    public var serverJweSecKey: SecKey { _serverJweSecKey }

    enum CodingKeys: CodingKey {
        case serverJwsPublicKey, serverJwePublicKey, opaqueContext, opaqueServerIdentifier
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let jwsJwk = try c.decode(JwkKey.self, forKey: .serverJwsPublicKey)
        let jweJwk = try c.decodeIfPresent(JwkKey.self, forKey: .serverJwePublicKey) ?? jwsJwk
        self.serverJwsPublicKey = jwsJwk
        self.serverJwePublicKey = jweJwk
        self.opaqueContext = try c.decode(Data.self, forKey: .opaqueContext)
        self.opaqueServerIdentifier = try c.decode(Data.self, forKey: .opaqueServerIdentifier)
        self._serverJwsSecKey = try jwsJwk.toSecKey()
        self._serverJweSecKey = try jweJwk.toSecKey()
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serverJwsPublicKey, forKey: .serverJwsPublicKey)
        try c.encode(serverJwePublicKey, forKey: .serverJwePublicKey)
        try c.encode(opaqueContext, forKey: .opaqueContext)
        try c.encode(opaqueServerIdentifier, forKey: .opaqueServerIdentifier)
    }

    // MARK: - Internal designated init

    init(serverJwsPublicKey: JwkKey, serverJwePublicKey: JwkKey, opaqueContext: Data, opaqueServerIdentifier: Data) throws {
        self.serverJwsPublicKey = serverJwsPublicKey
        self.serverJwePublicKey = serverJwePublicKey
        self.opaqueContext = opaqueContext
        self.opaqueServerIdentifier = opaqueServerIdentifier
        self._serverJwsSecKey = try serverJwsPublicKey.toSecKey()
        self._serverJweSecKey = try serverJwePublicKey.toSecKey()
    }

    // MARK: - Public inits

    /// Default test/dev server JWS public key PEM.
    private static let defaultServerPublicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpzQxuXLeiPyzitMKQbUSVOD3Axb+
    l9LqVjs5GnYanA1k4AmMUToWpITw5XXM48NPhbgMhoM0FUp4OQ26z/vCQQ==
    -----END PUBLIC KEY-----
    """

    /// Initializes with test/dev defaults (single key used for both JWS and JWE).
    public init(serverIdentifier: Data = Data("cloud-wallet.digg.se".utf8)) throws {
        try self.init(serverJwsPublicKeyPEM: Self.defaultServerPublicKeyPEM,
                      serverJwePublicKeyPEM: nil,
                      opaqueContext: Data("RPS-Ops".utf8),
                      opaqueServerIdentifier: serverIdentifier)
    }

    /// Initializes with PEM-encoded server keys and explicit OPAQUE parameters.
    ///
    /// - Parameters:
    ///   - serverJwsPublicKeyPEM: Server's JWS P-256 public key in PEM format.
    ///   - serverJwePublicKeyPEM: Server's JWE P-256 public key in PEM format.
    ///     Pass `nil` to use `serverJwsPublicKeyPEM` for both (single-key server config).
    ///   - opaqueContext: OPAQUE context (default: "RPS-Ops").
    ///   - opaqueServerIdentifier: OPAQUE server identifier (default: "cloud-wallet.digg.se").
    /// - Throws: If PEM parsing fails.
    public init(
        serverJwsPublicKeyPEM: String,
        serverJwePublicKeyPEM: String? = nil,
        opaqueContext: Data = Data("RPS-Ops".utf8),
        opaqueServerIdentifier: Data = Data("cloud-wallet.digg.se".utf8)
    ) throws {
        let jwsSecKey = try parseKey(serverJwsPublicKeyPEM)
        let jweSecKey = serverJwePublicKeyPEM != nil ? try parseKey(serverJwePublicKeyPEM!) : jwsSecKey
        let jwsJwk = try JwkKey.from(publicKey: jwsSecKey)
        let jweJwk = serverJwePublicKeyPEM != nil ? try JwkKey.from(publicKey: jweSecKey) : jwsJwk
        try self.init(serverJwsPublicKey: jwsJwk, serverJwePublicKey: jweJwk, opaqueContext: opaqueContext, opaqueServerIdentifier: opaqueServerIdentifier)
    }
}
