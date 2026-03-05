// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

// BFFHttpClient.swift
// Provisional HTTP client for early development.
// Wraps BFFLayer with HTTP transport to POST signed+encrypted messages to the HSM worker backend.

import Foundation
import JOSESwift
import Security
import OSLog

public struct BFFHttpClient {

    /// Result from ``authenticate(password:)``.
    public struct AuthenticationResult {
        /// OPAQUE session key (32 bytes) for symmetric encryption.
        public let sessionKey: Data
        /// OPAQUE export key (32 bytes).
        public let exportKey: Data
        /// Parsed server response.
        public let response: BFFLayer.ParsedBFFResponse
    }

    fileprivate let identity: BFFIdentity
    fileprivate let serverParameters: ServerParameters
    fileprivate let api: BFFLayer
    fileprivate let baseUrl: String
    fileprivate var session: ProtocolSession

    fileprivate let logRequestResponse: Bool = true

    enum APIError: Error {
        case parameterError
        case networkError
        case httpError(Int)
        case noPrivateKey
        case publicKeyExtractionFailed
    }

    public init(identity: BFFIdentity, serverParameters: ServerParameters, baseUrl: String) throws {
        guard let clientPrivateKey = identity.privateKey else {
            throw APIError.noPrivateKey
        }
        self.identity = identity
        self.serverParameters = serverParameters
        self.baseUrl = baseUrl
        self.session = try ProtocolSession(clientPrivateKey: clientPrivateKey, serverPublicKey: serverParameters.serverPublicKey)

        self.api = try BFFLayer(clientId: identity.clientId, serverParameters: serverParameters, opaqueClientId: identity.opaqueClientId(), devAuthorizationCode: identity.devAuthorizationCode)
    }

    /// Send a signed BFF request to the server and return the raw HTTP response body.
    ///
    /// This method performs a POST to `baseUrl + "/r2ps-api/service"` with content-type
    /// `application/json`. The `BFFRequest.outerRequestJws` (compact JWS string) is used as the
    /// HTTP body. The caller is responsible for parsing/verifying the returned bytes.
    ///
    /// - Parameters:
    ///   - request: The `BFFRequest` whose `outerRequestJws` is the compact JWS to send.
    /// - Throws:
    ///   - `APIError.parameterError` if the configured base URL is invalid.
    ///   - `APIError.networkError` if the response cannot be interpreted as an HTTP response.
    ///   - `APIError.httpError(statusCode)` when the server responds with a non-200 status.
    ///   - Any `URLSession` networking errors encountered while sending the request.
    /// - Returns: Raw response body `Data` (usually an outer JWS) for the caller to parse and validate.
    fileprivate func sendRequest(
        request: BFFRequest
    ) async throws -> Data {
        try await Self.sendRequest(baseUrl: self.baseUrl, body: request)
    }

    /// POST any JSON-encodable body to `baseUrl + path` and return raw response Data.
    ///
    /// Shared by signed JWS requests (path `/r2ps-api/service`) and plain JSON endpoints
    /// such as `new_state` (path `/r2ps-api/new_state`).
    private static func sendRequest<Body: Encodable>(
        baseUrl: String,
        path: String = "/r2ps-api/service",
        body: Body
    ) async throws -> Data {
        guard let url = URL(string: baseUrl + path) else {
            throw APIError.parameterError
        }

        let requestData = try JSONEncoder().encode(body)

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("*/*", forHTTPHeaderField: "Accept")
        urlRequest.httpBody = requestData
        urlRequest.timeoutInterval = 30.0

        let (data, response) = try await URLSession.shared.data(for: urlRequest)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.networkError
        }

        if httpResponse.statusCode != 200 {
            throw APIError.httpError(httpResponse.statusCode)
        }

        // Return raw response body bytes for caller to parse
        return data
    }

    /// Send a signed request from an OuterRequest and return the decoded response.
    ///
    /// This overload creates the BFFRequest from the OuterRequest, sends it, parses the response,
    /// and decodes the payload into the specified type.
    ///
    /// - Parameters:
    ///   - outerRequest: The `OuterRequest` to be signed and sent.
    ///   - session: The `ProtocolSession` used for encryption and response decryption.
    ///   - responseType: The type to decode the response payload into.
    /// - Throws: Any error from request creation, signing, network transport, or response parsing/decoding.
    /// - Returns: The decoded response of type `T`.
    fileprivate func sendRequest<T: Decodable>(
        outerRequest: OuterRequest,
        session: ProtocolSession,
        responseType: T.Type
    ) async throws -> T {
        let bffRequest = try self.api.createRequest(
            outerRequest: outerRequest,
            session: session,
            debugLog: self.logRequestResponse
        )

        let responseData = try await self.sendRequest(request: bffRequest)

        let parsed = try BFFLayer.parseAndValidateResponse(from: responseData, with: session, debugLog: self.logRequestResponse)
        return try parsed.decodePayload(responseType)
    }

    /// Performs OPAQUE registration (start + finish, two-phase protocol).
    ///
    /// Registers stretched PIN with server. First-time setup only.
    /// Use same password with ``authenticate(password:)`` for subsequent logins.
    ///
    /// - Parameter password: Stretched PIN from ``PINStretch/stretchPin(_:)``.
    /// - Returns: ``PakeResponse`` with registration result.
    /// - Throws: ``APIError`` if network fails or server rejects registration.
    public func registration(
        password: Data
    ) async throws -> PakeResponse {
        // Step 1: Build signed request + client state (use stored identifiers)
        let start = try self.api.registrationStart(
            password: password,
            with: self.session
        )

        // Send the signed start request and get raw response bytes
        let startResponseData = try await self.sendRequest(request: start.request)

        // Build finish request using parsed response bytes (delegate parsing to inner API)
        let finishRequest = try self.api.registrationFinish(start: start, responseData: startResponseData, with: self.session, logRequestResponse: self.logRequestResponse)

        // Send the finish request and get raw response bytes
        let finishResponseData = try await self.sendRequest(request: finishRequest)

        // Parse final response and return PAKE response
        let finishParsed = try BFFLayer.parseAndValidateResponse(from: finishResponseData, with: self.session, debugLog: self.logRequestResponse)
        let response = try finishParsed.decodePayload(PakeResponse.self)
        return response
    }

    /// Perform the OPAQUE authentication flow (start + finish) against the BFF service.
    ///
    /// This convenience method runs the two-step authentication protocol:
    /// 1. Build and sign an authenticate start request and POST it to the service.
    /// 2. Use the server's response to construct and send the authenticate finish request,
    ///    then parse and return the client finalization plus the server's PAKE response.
    ///
    /// - Parameters:
    ///   - password: The client's password bytes used for the OPAQUE protocol.
    /// - Throws: Any error raised while building, signing, sending, or parsing the protocol messages.
    /// - Returns: ``AuthenticationResult`` containing session key, export key, and server response.
    public mutating func authenticate(
        password: Data
    ) async throws -> AuthenticationResult {
        // Step 1: Build start request + client state (use stored identifiers)
        let start = try self.api.authenticateStart(
            password: password,
            with: self.session
        )

        // Send the start request and get raw response bytes
        let startResponseData = try await self.sendRequest(request: start.request)

        // Build finish request and client finalization using parsed response bytes (delegate parsing to inner API)
        let finish = try self.api.authenticateFinish(start: start, responseData: startResponseData, with: self.session, logRequestResponse: self.logRequestResponse)

        // Send the finish request and get raw response bytes
        let finishResponseData = try await self.sendRequest(request: finish.request)

        // Parse final response and return client finish + (full) response
        let finishParsed = try BFFLayer.parseAndValidateResponse(from: finishResponseData, with: self.session, debugLog: self.logRequestResponse)

        if let sessionId = finishParsed.outer.sessionId {
            try self.session.enterSession(sessionId: sessionId, sessionKey: finish.sessionKey)
        }

        return AuthenticationResult(
            sessionKey: finish.sessionKey,
            exportKey: finish.exportKey,
            response: finishParsed
        )
    }

    /// Requests HSM to generate new P-256 ECDSA key.
    ///
    /// Creates key in cloud HSM and returns key ID and public key in JWK format.
    /// Requires session mode (call after successful ``authenticate(password:)``).
    ///
    /// - Returns: ``HsmCreateKeyResponse`` with generated key's public key and ID.
    /// - Throws: ``APIError`` if request fails or not in session mode.
    public func createHsmKey() async throws -> HsmCreateKeyResponse {
        let request = try ProtocolRequest.hsmGenerateKey()

        return try await self.sendRequest(outerRequest: request, session: self.session, responseType: HsmCreateKeyResponse.self)
    }

    /// Lists all HSM keys for current session.
    ///
    /// Requires session mode (call after successful ``authenticate(password:)``).
    ///
    /// - Returns: ``HsmListResponse`` with array of key metadata (``HsmKeyInfo``).
    /// - Throws: ``APIError`` if request fails or not in session mode.
    public func listKeys() async throws -> HsmListResponse {
        let request = try ProtocolRequest.hsmListKeys()

        return try await self.sendRequest(outerRequest: request, session: self.session, responseType: HsmListResponse.self)
    }

    /// Requests HSM to sign a SHA-256 digest with specified key.
    ///
    /// Caller must pre-hash the data: `Data(SHA256.hash(data: data))`.
    ///
    /// - Parameters:
    ///   - hsmKeyId: HSM key ID (from ``HsmCreateKeyResponse/public_key`` `kid` or ``HsmKeyInfo/kid``).
    ///   - digest: SHA-256 digest to sign (32 bytes).
    /// - Returns: ``SignatureResponse`` with base64-encoded DER signature.
    /// - Throws: ``APIError`` if request fails.
    public func sign(hsmKeyId: String, digest: Data) async throws -> SignatureResponse {
        let request = try ProtocolRequest.hsmSign(hsmKid: hsmKeyId, message: digest)

        return try await self.sendRequest(outerRequest: request, session: self.session, responseType: SignatureResponse.self)
    }

    // MARK: - Factories

    /// Registers a new device with the server by calling `/r2ps-api/new_state`.
    ///
    /// - Parameters:
    ///   - baseUrl: Base URL of the BFF service.
    ///   - publicKey: Device public key (P-256) to register.
    ///   - overwrite: If true, replaces existing registration for this key.
    ///   - ttl: Optional session TTL hint.
    /// - Returns: Server response with assigned client ID and optional dev authorization code.
    /// - Throws: Network or server errors.
    public static func registerNewDevice(
        baseUrl: String,
        publicKey: SecKey,
        overwrite: Bool = false,
        ttl: String? = nil
    ) async throws -> NewStateResponse {
        let jwk = try JwkKey.from(publicKey: publicKey)
        let responseData = try await Self.sendRequest(
            baseUrl: baseUrl,
            path: "/r2ps-api/new_state",
            body: NewStateRequest(publicKey: jwk, clientId: nil, overwrite: overwrite, ttl: ttl)
        )
        return try JSONDecoder().decode(NewStateResponse.self, from: responseData)
    }

    /// Creates a new client: generates a Secure Enclave key, registers with `new_state`, returns client + identity.
    ///
    /// Persist `identity` via ``BFFIdentity/toClientIdentity()`` (e.g. `JSONEncoder` → UserDefaults).
    /// Restore on next launch with ``loadClient(baseUrl:identity:serverParameters:)``.
    ///
    /// - Parameters:
    ///   - baseUrl: Base URL of the BFF service (e.g. `"http://localhost:8088"`).
    ///   - serverParameters: Server crypto parameters.
    ///   - ttl: Optional session TTL hint passed to server.
    /// - Returns: Configured client and identity.
    /// - Throws: Key generation, network, or server errors.
    public static func createClient(
        baseUrl: String,
        serverParameters: ServerParameters,
        ttl: String? = nil
    ) async throws -> (client: BFFHttpClient, identity: BFFIdentity) {
        let keyTag = UUID().uuidString
        let privateKey = try BFFIdentity.generateKey(tag: keyTag)
        guard let clientPublicKey = SecKeyCopyPublicKey(privateKey) else {
            throw APIError.publicKeyExtractionFailed
        }
        let jwk = try JwkKey.from(publicKey: clientPublicKey)

        let responseData = try await Self.sendRequest(
            baseUrl: baseUrl,
            path: "/r2ps-api/new_state",
            body: NewStateRequest(publicKey: jwk, clientId: nil, overwrite: false, ttl: ttl)
        )
        let newStateResponse = try JSONDecoder().decode(NewStateResponse.self, from: responseData)

        guard newStateResponse.status == .ok, let clientId = newStateResponse.clientId else {
            throw APIError.parameterError
        }

        let identity = BFFIdentity(clientId: clientId, keyTag: keyTag, devAuthorizationCode: newStateResponse.devAuthorizationCode, privateKey: privateKey)
        let client = try BFFHttpClient(identity: identity, serverParameters: serverParameters, baseUrl: baseUrl)
        return (client, identity)
    }

}
