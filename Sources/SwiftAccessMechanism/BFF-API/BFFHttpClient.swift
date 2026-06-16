// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

import Foundation
import Security

/// BFF protocol client with injectable transport.
///
/// Use `BFFHttpClient.create(transport:privateKey:)` as the primary entry point.
/// - For direct-to-BFF access: `BFFHttpClient.createClient(baseUrl:serverParameters:)`.
/// - For gateway-proxied access (wallet app): pass `GatewayApiClient` as transport.
public actor BFFHttpClient {

    public struct AuthenticationResult: Sendable {
        public let sessionKey: Data
        public let exportKey: Data
        public let response: BFFLayer.ParsedBFFResponse

        public init(sessionKey: Data, exportKey: Data, response: BFFLayer.ParsedBFFResponse) {
            self.sessionKey = sessionKey
            self.exportKey = exportKey
            self.response = response
        }
    }

    private let transport: any BFFTransport
    private let layer: BFFLayer
    private var session: ProtocolSession

    public let clientId: String
    public let serverParameters: ServerParameters

#if DEBUG
    private let logEnabled = true
#else
    private let logEnabled = false
#endif

    init(transport: any BFFTransport, layer: BFFLayer, session: ProtocolSession, clientId: String, serverParameters: ServerParameters) {
        self.transport = transport
        self.layer = layer
        self.session = session
        self.clientId = clientId
        self.serverParameters = serverParameters
    }

    // MARK: - Factories

    /// Registers a device key with the server and initialises the BFF session.
    ///
    /// Primary entry point for both gateway-proxied and direct transport.
    public static func create(
        transport: any BFFTransport,
        privateKey: SecKey,
        serverParameters: ServerParameters? = nil,
        ttl: String? = nil
    ) async throws -> BFFHttpClient {
        guard let pubKeyRef = SecKeyCopyPublicKey(privateKey) else {
            throw Error.publicKeyExtractionFailed
        }
        let jwk = try JwkKey.from(publicKey: pubKeyRef)
        var serverParams = try serverParameters ?? ServerParameters()
        let stateResponse = try await transport.registerState(publicKey: jwk, overwrite: false, ttl: ttl)
      
        if let serverJwk = stateResponse.serverJwsPublicKey,
           let opaqueServerId = stateResponse.opaqueServerId {
            serverParams = try ServerParameters(
                serverJwsPublicKey: serverJwk,
                opaqueContext: serverParams.opaqueContext,
                opaqueServerIdentifier: Data(opaqueServerId.utf8)
            )
        }
      
        let opaqueClientId = Data((jwk.kid ?? "").utf8)
        let layer = try BFFLayer(
            clientId: stateResponse.clientId,
            serverParameters: serverParams,
            opaqueClientId: opaqueClientId,
            devAuthorizationCode: stateResponse.devAuthorizationCode
        )
        let protocolSession = try ProtocolSession(
            clientPrivateKey: privateKey,
            serverPublicKey: serverParams.serverPublicKey,
            serverKid: serverParams.serverJwsPublicKey.kid ?? ""
        )
        return BFFHttpClient(transport: transport, layer: layer, session: protocolSession, clientId: stateResponse.clientId, serverParameters: serverParams)
    }

    /// Resumes a previously registered BFF session using a known client ID and private key.
    ///
    /// Use this when the client ID has been persisted across launches and the caller has already
    /// resolved the `SecKey` (e.g. from Keychain). No network call is made.
    public static func resume(
        transport: any BFFTransport,
        clientId: String,
        privateKey: SecKey,
        serverParameters: ServerParameters
    ) throws -> BFFHttpClient {
        guard let pubKeyRef = SecKeyCopyPublicKey(privateKey) else {
            throw Error.publicKeyExtractionFailed
        }
        let jwk = try JwkKey.from(publicKey: pubKeyRef)
        let opaqueClientId = Data((jwk.kid ?? "").utf8)
        let layer = try BFFLayer(
            clientId: clientId,
            serverParameters: serverParameters,
            opaqueClientId: opaqueClientId,
            devAuthorizationCode: nil
        )
        let protocolSession = try ProtocolSession(
            clientPrivateKey: privateKey,
            serverPublicKey: serverParameters.serverPublicKey,
            serverKid: serverParameters.serverJwsPublicKey.kid ?? ""
        )
        return BFFHttpClient(transport: transport, layer: layer, session: protocolSession, clientId: clientId, serverParameters: serverParameters)
    }

    /// Creates a direct-to-BFF client using URLSessionBFFTransport.
    /// Generates a new SE key, registers with the server, returns client + identity.
    public static func createClient(
        baseUrl: String,
        serverParameters: ServerParameters,
        ttl: String? = nil
    ) async throws -> (client: BFFHttpClient, identity: BFFIdentity) {
        let keyTag = UUID().uuidString
        let privateKey = try BFFIdentity.generateKey(tag: keyTag)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw Error.publicKeyExtractionFailed
        }
        let transport = URLSessionBFFTransport(baseUrl: baseUrl)
        let jwk = try JwkKey.from(publicKey: publicKey)
        let stateResponse = try await transport.registerState(publicKey: jwk, overwrite: false, ttl: ttl)
      
        var effectiveParams = serverParameters
        if let serverJwk = stateResponse.serverJwsPublicKey, let opaqueServerId = stateResponse.opaqueServerId {
            effectiveParams = try ServerParameters(
                serverJwsPublicKey: serverJwk,
                opaqueContext: serverParameters.opaqueContext,
                opaqueServerIdentifier: Data(opaqueServerId.utf8)
            )
        }
      
        let identity = BFFIdentity(
            clientId: stateResponse.clientId,
            keyTag: keyTag,
            devAuthorizationCode: stateResponse.devAuthorizationCode,
            privateKey: privateKey
        )
        let opaqueClientId = Data((jwk.kid ?? "").utf8)
        let layer = try BFFLayer(
            clientId: stateResponse.clientId,
            serverParameters: effectiveParams,
            opaqueClientId: opaqueClientId,
            devAuthorizationCode: stateResponse.devAuthorizationCode
        )
        let protocolSession = try ProtocolSession(
            clientPrivateKey: privateKey,
            serverPublicKey: effectiveParams.serverPublicKey,
            serverKid: effectiveParams.serverJwsPublicKey.kid ?? ""
        )
        return (BFFHttpClient(transport: transport, layer: layer, session: protocolSession, clientId: stateResponse.clientId, serverParameters: effectiveParams), identity)
    }

    // MARK: - OPAQUE Registration

    public func registration(password: StretchedPIN) async throws -> PakeResponse {
        let start = try layer.registrationStart(password: password, with: session)
        let startData = try await transport.registerPin(request: start.request)
        let finish = try layer.registrationFinish(start: start, responseData: startData, with: session)
        let finishData = try await transport.registerPin(request: finish)
        let parsed = try BFFLayer.parseAndValidateResponse(from: finishData, with: session, debugLog: logEnabled)
        return try parsed.decodePayload(PakeResponse.self)
    }

    // MARK: - OPAQUE Authentication

    public func authenticate(password: StretchedPIN) async throws -> AuthenticationResult {
        let start = try layer.authenticateStart(password: password, with: session)
        let startData = try await transport.createSession(request: start.request)
        let finish = try layer.authenticateFinish(start: start, responseData: startData, with: session)
        let finishData = try await transport.createSession(request: finish.request)
        let parsed = try BFFLayer.parseAndValidateResponse(from: finishData, with: session, debugLog: logEnabled)
        if let sessionId = parsed.outer.sessionId {
            try session.enterSession(sessionId: sessionId, sessionKey: finish.sessionKey)
        }
        return AuthenticationResult(
            sessionKey: finish.sessionKey,
            exportKey: finish.exportKey,
            response: parsed
        )
    }

    // MARK: - PIN Change

    /// Changes the PIN using OPAQUE registration flow (start + finish, two-phase protocol).
    ///
    /// Requires an active session (call after ``authenticate(password:)``).
    /// The server destroys the session after a successful PIN change — the client
    /// session is reset to device mode, requiring re-authentication before further requests.
    ///
    /// - Parameter newPassword: Stretched new PIN from ``PINStretch/stretchPin(_:)``.
    public func changePin(newPassword: StretchedPIN) async throws {
        let start = try layer.changePinStart(newPassword: newPassword, with: session)
        let startData = try await transport.changePin(request: start.request)
        let finishRequest = try layer.changePinFinish(start: start, responseData: startData, with: session)
        let finishData = try await transport.changePin(request: finishRequest)
        _ = try BFFLayer.parseAndValidateResponse(from: finishData, with: session, debugLog: logEnabled)
        try session.exitSession()
    }

    // MARK: - HSM Operations

    public func createHsmKey() async throws -> HsmCreateKeyResponse {
        let req = try layer.createRequest(
            outerRequest: try ProtocolRequest.hsmGenerateKey(),
            session: session
        )
        let data = try await transport.createKey(request: req)
        let parsed = try BFFLayer.parseAndValidateResponse(from: data, with: session, debugLog: logEnabled)
        return try parsed.decodePayload(HsmCreateKeyResponse.self)
    }

    public func listKeys() async throws -> HsmListResponse {
        let req = try layer.createRequest(
            outerRequest: try ProtocolRequest.hsmListKeys(),
            session: session
        )
        let data = try await transport.listKeys(request: req)
        let parsed = try BFFLayer.parseAndValidateResponse(from: data, with: session, debugLog: logEnabled)
        return try parsed.decodePayload(HsmListResponse.self)
    }

    public func sign(hsmKeyId: String, digest: Data) async throws -> SignatureResponse {
        let req = try layer.createRequest(
            outerRequest: try ProtocolRequest.hsmSign(hsmKid: hsmKeyId, message: digest),
            session: session
        )
        let data = try await transport.sign(request: req)
        let parsed = try BFFLayer.parseAndValidateResponse(from: data, with: session, debugLog: logEnabled)
        return try parsed.decodePayload(SignatureResponse.self)
    }

    public func deleteKey(hsmKeyId: String) async throws {
        let req = try layer.createRequest(
            outerRequest: try ProtocolRequest.hsmDeleteKey(hsmKid: hsmKeyId),
            session: session
        )
        try await transport.deleteKey(request: req)
    }

    public enum Error: Swift.Error {
        case publicKeyExtractionFailed
    }
}
