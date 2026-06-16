// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

import Foundation

public struct RegisterStateResponse: Sendable {
    public let clientId: String
    public let devAuthorizationCode: String?

    public init(clientId: String, devAuthorizationCode: String?) {
        self.clientId = clientId
        self.devAuthorizationCode = devAuthorizationCode
    }
}

/// - `URLSessionBFFTransport` is the built-in direct-to-BFF implementation.
/// - `GatewayApiClient` (WalletGateway) conforms to this for gateway-proxied use.
///
/// All JWT-carrying methods receive a fully-constructed `BFFRequest` (which bundles
/// `clientId` and `outerRequestJws`). Gateway implementations use only `outerRequestJws`;
/// the URLSession implementation uses both fields to build the request body.
///
/// Methods return `Data` (not `String`) so callers can pass results directly to
/// `BFFLayer.registrationFinish(start:responseData:with:)` and `authenticateFinish`
/// without an intermediate `Data(string.utf8)` conversion.
public protocol BFFTransport: Sendable {
    func registerState(publicKey: JwkKey, overwrite: Bool, ttl: String?) async throws -> RegisterStateResponse
    func registerPin(request: BFFRequest) async throws -> Data
    func createSession(request: BFFRequest) async throws -> Data
    func changePin(request: BFFRequest) async throws -> Data
    func createKey(request: BFFRequest) async throws -> Data
    func listKeys(request: BFFRequest) async throws -> Data
    func sign(request: BFFRequest) async throws -> Data
    func deleteKey(request: BFFRequest) async throws
}
