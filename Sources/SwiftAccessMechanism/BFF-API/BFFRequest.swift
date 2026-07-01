// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  HSMRequest.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-28.
//

/*
 JWT/JWE-focused API for constructing and verifying BFF protocol messages.
 Independent of HTTP transport; exposes only cryptographic helpers and request builders.

 The outer HTTP transport (send/receive) is implemented in `BFFHttpClient` and
 should consume `BFFLayer` but not the other way around.
 */

import Foundation
import JOSESwift
import CryptoKit
import Security
import OSLog

/// Transport-independent message builder for JWS/JWE protocol messages.
///
/// Builds and parses Protocol layer messages without HTTP coupling. Use ``BFFHttpClient`` for provisional HTTP transport,
/// or use ``BFFLayer`` directly when implementing custom transport.
///
/// **Note:** Provisional implementation for project early life. Can be used with HTTP transport, or replaced with custom transport using ``ProtocolSession`` and ``OuterRequest``/``OuterResponse`` directly.
///
/// ## Example
///
/// ```swift
/// let layer = BFFLayer(
///     clientId: "client-id",
///     serverParameters: serverParams,
///     opaqueClientId: clientIdData
/// )
///
/// // Build request
/// let bffRequest = try layer.buildPakeRegistrationStartRequest(password: stretchedPin)
/// // Send bffRequest.request (String) via your transport
///
/// // Parse response
/// let parsed = try layer.parsePakeRegistrationStartResponse(serverResponse: responseString)
/// ```
public struct BFFLayer: Sendable {
    // Errors used by the inner API (independent of HTTP client)
    enum APIError: Error {
        case parameterError
        case networkError
        case httpError(Int)
        case invalidSignature
        case unexpectedEncryption(String)
    }

    fileprivate let logRequestResponse: Bool = true
    fileprivate let clientId: String? // For HSMRequest
    fileprivate let serverParameters: ServerParameters
    fileprivate let opaqueClientId: Data // For OPAQUE operations
    fileprivate let devAuthorizationCode: String? // DEV-ONLY: required for registration

    /// Parsed BFF response with typed payload decoding.
    public struct ParsedBFFResponse: Sendable {
        /// Outer response (JWS layer).
        public let outer: OuterResponse

        /// Decodes response payload to typed model.
        ///
        /// - Parameter type: Expected response type.
        /// - Returns: Decoded response object.
        /// - Throws: Decoding errors.
        public func decodePayload<T: Decodable>(_ type: T.Type) throws -> T {
            if outer.innerResponse.status == .error {
                throw ServerError(message: outer.innerResponse.errorMessage ?? "Unknown inner error")
            }
            let payload = outer.innerResponse.data?.data(using: .utf8) ?? Data()
            do {
                return try JSONDecoder().decode(type, from: payload)
            } catch {
                // Log helpful debug information for failing payloads
                if let asText = String(data: payload, encoding: .utf8) {
                    Logger.api.error("Failed to decode payload as \(String(describing: type)): \(error). Payload (utf8): \(asText)")
                } else {
                    Logger.api.error("Failed to decode payload as \(String(describing: type)): \(error). Payload (hex): \(payload.hexString())")
                }
                throw error
            }
        }
    }

    // Return type for authenticateFinish: both the signed finish request and the client finalization result
    public struct AuthenticateFinishResult {
        public let request: HSMRequest
        public let sessionKey: Data
        public let exportKey: Data
    }

    // A small container for the results returned by the "start" helpers
    public struct PAKEStartResult {
        public let request: HSMRequest
        public let clientRegistration: Data
        // stored values required for finish
        public let password: StretchedPIN
        public let authorization: String?
    }

    public init(clientId: String? = nil, serverParameters: ServerParameters, opaqueClientId: Data, devAuthorizationCode: String? = nil) throws {
        self.clientId = clientId
        self.serverParameters = serverParameters
        self.opaqueClientId = opaqueClientId
        self.devAuthorizationCode = devAuthorizationCode
    }

    private func logJWSComponents(_ jwsString: String, label: String) {
        // Manually parse components to log the raw header JSON, avoiding Encodable constraints on JWSHeader objects
        let components = jwsString.components(separatedBy: ".")
        if components.count >= 1,
           let headerData = Data(base64URLEncoded: components[0]),
           let headerStr = String(data: headerData, encoding: .utf8) {
            Logger.api.debug("\(label) headers: \(headerStr)")
        }

        if components.count >= 2,
           let rawPayload = Data(base64URLEncoded: components[1]) {
            if let payloadStr = String(data: rawPayload, encoding: .utf8) {
                Logger.api.debug("\(label) payload: \(payloadStr)")
            } else {
                Logger.api.debug("\(label) payload (hex): \(rawPayload.hexString())")
            }
        }
    }

    // Create and sign a JWS payload and wrap in HSMRequest
    public func createRequest(outerRequest: OuterRequest, session: ProtocolSession, debugLog: Bool = false) throws -> HSMRequest {
        let jwsString = try outerRequest.toJWS(signer: session.signer, session: session)

        if debugLog {
            self.logJWSComponents(jwsString, label: "Created JWS request")
            Logger.api.debug("Created JWS request: \(jwsString)")
        }

        return HSMRequest(
            clientId: self.clientId,
            outerRequestJws: jwsString
        )
    }

    // Accept raw response bytes directly and delegate to string-based parser
    public static func parseAndValidateResponse(from responseData: Data, with session: ProtocolSession, debugLog: Bool) throws -> ParsedBFFResponse {
        guard let jwsString = String(data: responseData, encoding: .utf8) else {
            Logger.api.error("Response is not valid UTF-8: \(responseData.hexString())")
            throw BFFLayer.APIError.networkError
        }
        return try BFFLayer.parseAndValidateResponse(from: jwsString, with: session, debugLog: debugLog)
    }

    // Parse and validate the HTTP/JWS response, decrypt inner JWE and return a wrapper
    public static func parseAndValidateResponse(from jwsString: String, with session: ProtocolSession, debugLog: Bool) throws -> ParsedBFFResponse {
        if debugLog {
            Logger.api.debug("Received response (JWS): \(jwsString)")
        }

        // Verify request JWS and extract payload (OuterResponse logic)
        let outerResponse: OuterResponse
        do {
            outerResponse = try OuterResponse(jwsString: jwsString, session: session)
        } catch OuterResponse.Error.invalidSignature {
            throw BFFLayer.APIError.invalidSignature
        } catch OuterResponse.Error.unexpectedEncryption(let kids) {
            throw BFFLayer.APIError.unexpectedEncryption(kids)
        } catch {
            Logger.api.error("Failed to decode outer Response: \(error)")
            throw error
        }

        let innerResponse: InnerResponse = outerResponse.innerResponse

        Logger.api.debug("Inner response data (string): \(innerResponse.data ?? "")")

        // Return raw decrypted payload; callers can decode it via ParsedBFFResponse.decodePayload(_:)
        return ParsedBFFResponse(outer: outerResponse)
    }

    // Shortcuts for constructing PAKE requests using the OPAQUE client helpers
    public func registrationStart(
        password: StretchedPIN,
        with session: ProtocolSession
    ) throws -> PAKEStartResult {
        let start = try ProtocolRequest.registrationStart(password: password, authorization: self.devAuthorizationCode)

        let bffRequest = try self.createRequest(
            outerRequest: start.outerRequest,
            session: session,
            debugLog: self.logRequestResponse
        )

        return PAKEStartResult(request: bffRequest,
                               clientRegistration: start.clientRegistration,
                               password: password,
                               authorization: start.authorization)
    }

    // accept raw response Data and build the registration finish request
    public func registrationFinish(start: PAKEStartResult, responseData: Data, with session: ProtocolSession,
                                   logRequestResponse: Bool = false) throws -> HSMRequest {
        // Parse outer JWS, decrypt inner JWE and obtain PAKE response
        let parsed = try BFFLayer.parseAndValidateResponse(from: responseData, with: session, debugLog: logRequestResponse)
        let pake = try parsed.decodePayload(PakeResponse.self)
        let credentialResponse = try pake.decodedResponseData()

        // Delegate to existing inner registrationFinish that accepts credential bytes
        return try self.registrationFinish(start: start, credentialResponse: credentialResponse, with: session)
    }

    func registrationFinish(
        start: PAKEStartResult,
        credentialResponse: Data,
        with session: ProtocolSession
    ) throws -> HSMRequest {
        let clientFinish = try OpaqueClient.registrationFinish(
            clientRegistration: start.clientRegistration,
            password: start.password.data,
            registrationResponse: credentialResponse,
            clientIdentifier: self.opaqueClientId,
            serverIdentifier: self.serverParameters.opaqueServerIdentifier
        )

        let regKE3 = clientFinish.registrationUpload.base64EncodedString()

        let finishPakeRequest = PakeRequest(
            authorization: start.authorization,
            purpose: nil,
            sessionDuration: nil,
            requestData: regKE3
        )

        let innerRequest = try InnerRequest(type: .registerFinish, jsonData: finishPakeRequest)
        let outerRequest = OuterRequest(
            inner: innerRequest,
        )

        let bffRequest = try self.createRequest(
            outerRequest: outerRequest,
            session: session,
            debugLog: self.logRequestResponse
        )

        return bffRequest
    }

    func changePinStart(
        newPassword: StretchedPIN,
        with session: ProtocolSession
    ) throws -> PAKEStartResult {
        let start = try ProtocolRequest.changePinStart(newPassword: newPassword)

        let bffRequest = try self.createRequest(
            outerRequest: start.outerRequest,
            session: session,
            debugLog: self.logRequestResponse
        )

        return PAKEStartResult(request: bffRequest,
                               clientRegistration: start.clientRegistration,
                               password: newPassword,
                               authorization: nil)
    }

    func changePinFinish(start: PAKEStartResult, responseData: Data, with session: ProtocolSession) throws -> HSMRequest {
        let parsed = try BFFLayer.parseAndValidateResponse(from: responseData, with: session, debugLog: self.logRequestResponse)
        let pake = try parsed.decodePayload(PakeResponse.self)
        let credentialResponse = try pake.decodedResponseData()

        let clientFinish = try OpaqueClient.registrationFinish(
            clientRegistration: start.clientRegistration,
            password: start.password.data,
            registrationResponse: credentialResponse,
            clientIdentifier: self.opaqueClientId,
            serverIdentifier: self.serverParameters.opaqueServerIdentifier
        )

        let regKE3 = clientFinish.registrationUpload.base64EncodedString()

        let finishPakeRequest = PakeRequest(
            authorization: nil,
            purpose: nil,
            sessionDuration: nil,
            requestData: regKE3
        )

        let innerRequest = try InnerRequest(type: .changePinFinish, jsonData: finishPakeRequest)
        let outerRequest = OuterRequest(inner: innerRequest)

        return try self.createRequest(
            outerRequest: outerRequest,
            session: session,
            debugLog: self.logRequestResponse
        )
    }

    public func authenticateStart(
        password: StretchedPIN,
        with session: ProtocolSession
    ) throws -> PAKEStartResult {
        let start = try ProtocolRequest.authenticateStart(password: password)

        let bffRequest = try self.createRequest(
            outerRequest: start.outerRequest,
            session: session,
            debugLog: self.logRequestResponse
        )

        return PAKEStartResult(request: bffRequest,
                               clientRegistration: start.clientRegistration,
                               password: password,
                               authorization: nil)
    }

    // accept raw response Data and build the authenticate finish request + client finalization
    public func authenticateFinish(start: PAKEStartResult, responseData: Data, with session: ProtocolSession, logRequestResponse: Bool = false) throws -> AuthenticateFinishResult {
        let parsed = try BFFLayer.parseAndValidateResponse(from: responseData, with: session, debugLog: logRequestResponse)
        let pake = try parsed.decodePayload(PakeResponse.self)
        let credentialResponse = try pake.decodedResponseData()

        guard let sessionId = parsed.outer.sessionId else {
            throw BFFLayer.APIError.parameterError
        }

        return try self.authenticateFinish(start: start, credentialResponse: credentialResponse, sessionId: sessionId, with: session)
    }

    func authenticateFinish(
        start: PAKEStartResult,
        credentialResponse: Data,
        sessionId: String,
        with session: ProtocolSession
    ) throws -> AuthenticateFinishResult {
        let finish = try ProtocolRequest.authenticateFinish(
            clientRegistration: start.clientRegistration,
            password: start.password,
            credentialResponse: credentialResponse,
            context: self.serverParameters.opaqueContext,
            clientIdentifier: self.opaqueClientId,
            serverIdentifier: self.serverParameters.opaqueServerIdentifier,
            sessionId: sessionId,
        )

        let sessionRequest = try self.createRequest(
            outerRequest: finish.outerRequest,
            session: session,
            debugLog: self.logRequestResponse
        )

        return AuthenticateFinishResult(request: sessionRequest, sessionKey: finish.sessionKey, exportKey: finish.exportKey)
    }
}
