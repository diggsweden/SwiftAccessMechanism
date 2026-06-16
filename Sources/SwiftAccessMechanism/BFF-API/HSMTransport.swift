// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

import Foundation

public struct RegisterStateResponse: Sendable {
    public let clientId: String
    public let devAuthorizationCode: String?
    /// Server's current JWS public key — use for device-mode encryption when present.
    public let serverJwsPublicKey: JwkKey?
    /// OPAQUE server identifier returned by server.
    public let opaqueServerId: String?

    public init(clientId: String, devAuthorizationCode: String?, serverJwsPublicKey: JwkKey? = nil, opaqueServerId: String? = nil) {
        self.clientId = clientId
        self.devAuthorizationCode = devAuthorizationCode
        self.serverJwsPublicKey = serverJwsPublicKey
        self.opaqueServerId = opaqueServerId
    }
}

/// Identifies the HSM operation being performed, used for logging and tracing.
public enum HSMOperation: String, Sendable {
    case registerPin
    case createSession
    case changePin
    case createKey
    case listKeys
    case sign
    case deleteKey
}

/// - `URLSessionHSMTransport` is the built-in direct-to-BFF implementation.
/// - `GatewayApiClient` (WalletGateway) conforms to this for gateway-proxied use.
///
/// All JWT-carrying methods receive a fully-constructed `HSMRequest` (which bundles
/// `clientId` and `outerRequestJws`). Gateway implementations use only `outerRequestJws`;
/// the URLSession implementation uses both fields to build the request body.
///
/// `perform` returns `Data` (not `String`) so callers can pass results directly to
/// `BFFLayer.registrationFinish(start:responseData:with:)` and `authenticateFinish`
/// without an intermediate `Data(string.utf8)` conversion.
public protocol HSMTransport: Sendable {
    func registerState(publicKey: JwkKey, overwrite: Bool, ttl: String?) async throws -> RegisterStateResponse
    @discardableResult
    func perform(_ request: HSMRequest, operation: HSMOperation) async throws -> Data
}
