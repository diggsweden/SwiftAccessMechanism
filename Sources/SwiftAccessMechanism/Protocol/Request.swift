// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  Request.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2026-02-04.
//
import Foundation

/// Convenience builders for typed Protocol layer requests.
///
/// Provides static methods for all operations: OPAQUE registration/authentication and HSM operations.
/// Returns ``OuterRequest`` ready to sign with ``OuterRequest/toJWS(signingKey:)``.
public struct ProtocolRequest {
    /// Result from OPAQUE registration/authentication start operations.
    struct RegistrationStartResult {
        /// Outer request ready to sign and send to server.
        let outerRequest: OuterRequest
        /// OPAQUE client state (pass to finish method).
        let clientRegistration: Data
        /// Authorization code (pass to finish method).
        let authorization: String?
    }

    /// Result from OPAQUE authentication or PIN-change start.
    struct AuthenticateStartResult {
        /// Outer request ready to sign and send to server.
        let outerRequest: OuterRequest
        /// OPAQUE client state (pass to finish method).
        let clientRegistration: Data
    }

    /// Starts OPAQUE registration.
    ///
    /// - Parameters:
    ///   - password: Stretched PIN from ``PINStretch/stretchPin(_:)``.
    ///   - authorization: Optional authorization code (dev-only).
    /// - Returns: ``RegistrationStartResult`` with outer request and client state.
    /// - Throws: ``OpaqueClientError`` if OPAQUE operation fails.
    static func registrationStart(password: StretchedPIN, authorization: String? = nil) throws -> RegistrationStartResult {
        let clientStart = try OpaqueClient.registrationStart(password: password.data)
        let regKE1 = clientStart.registrationRequest.base64EncodedString()

        let startPakeRequest = PakeRequest(
            authorization: authorization,
            purpose: nil,
            sessionDuration: nil,
            requestData: regKE1
        )

        let innerRequest = try InnerRequest(type: .registerStart, jsonData: startPakeRequest)
        let outerRequest = OuterRequest(
            inner: innerRequest,
        )

        return RegistrationStartResult(outerRequest: outerRequest, clientRegistration: clientStart.clientRegistration, authorization: authorization)
    }

    /// Starts OPAQUE authentication.
    ///
    /// - Parameter password: Stretched PIN from ``PINStretch/stretchPin(_:)`` (must match registration).
    /// - Returns: ``AuthenticateStartResult`` with outer request and client state.
    /// - Throws: ``OpaqueClientError`` if OPAQUE operation fails.
    static func authenticateStart(password: StretchedPIN) throws -> AuthenticateStartResult {
        let clientStart = try OpaqueClient.authenticateStart(password: password.data)
        let authKE1 = clientStart.credentialRequest.base64EncodedString()

        let startPakeRequest = PakeRequest(
            authorization: nil,
            purpose: nil,
            sessionDuration: nil,
            requestData: authKE1
        )

        let innerRequest = try InnerRequest(type: .authenticateStart, jsonData: startPakeRequest)
        let outerRequest = OuterRequest(inner: innerRequest)

        return AuthenticateStartResult(outerRequest: outerRequest, clientRegistration: clientStart.clientRegistration)
    }

    /// Finishes OPAQUE registration.
    ///
    /// - Parameters:
    ///   - start: Result from ``registrationStart(password:authorization:)``.
    ///   - password: Same stretched PIN used in registration start.
    ///   - credentialResponse: Server's registration response (from ``PakeResponse/responseData``).
    ///   - clientIdentifier: Client identifier (typically username as UTF-8 data).
    ///   - serverIdentifier: Server identifier (from ``ServerParameters/opaqueServerIdentifier``).
    /// - Returns: ``OuterRequest`` ready to sign and send.
    /// - Throws: ``OpaqueClientError`` if OPAQUE operation fails.
    static func registrationFinish(
        start: RegistrationStartResult,
        password: StretchedPIN,
        credentialResponse: Data,
        clientIdentifier: Data,
        serverIdentifier: Data
    ) throws -> OuterRequest {
        let clientFinish = try OpaqueClient.registrationFinish(
            clientRegistration: start.clientRegistration,
            password: password.data,
            registrationResponse: credentialResponse,
            clientIdentifier: clientIdentifier,
            serverIdentifier: serverIdentifier
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

        return outerRequest
    }

    /// Result from OPAQUE authentication finish.
    struct FinishResult {
        /// Outer request ready to sign and send to server.
        let outerRequest: OuterRequest
        /// Session key for symmetric encryption (pass to ``ProtocolSession/enterSession(sessionId:sessionKey:)``).
        let sessionKey: Data
        /// Export key from OPAQUE protocol.
        let exportKey: Data
    }

    /// Finishes OPAQUE authentication.
    ///
    /// - Parameters:
    ///   - clientRegistration: Client state from ``authenticateStart(password:)``.
    ///   - password: Same stretched PIN used in authentication start.
    ///   - credentialResponse: Server's authentication response (from ``PakeResponse/responseData``).
    ///   - context: OPAQUE context (from ``ServerParameters/opaqueContext``).
    ///   - clientIdentifier: Client identifier (same username used in registration).
    ///   - serverIdentifier: Server identifier (from ``ServerParameters/opaqueServerIdentifier``).
    ///   - sessionId: Session ID from server response (``PakeResponse/sessionId``).
    /// - Returns: ``FinishResult`` with outer request and session key.
    /// - Throws: ``OpaqueClientError`` if OPAQUE operation fails.
    static func authenticateFinish(
        clientRegistration: Data,
        password: StretchedPIN,
        credentialResponse: Data,
        context: Data,
        clientIdentifier: Data,
        serverIdentifier: Data,
        sessionId: String
    ) throws -> FinishResult {
        let clientFinish = try OpaqueClient.authenticateFinish(
            clientRegistration: clientRegistration,
            password: password.data,
            credentialResponse: credentialResponse,
            context: context,
            clientIdentifier: clientIdentifier,
            serverIdentifier: serverIdentifier
        )

        let authKE3 = clientFinish.credentialFinalization.base64EncodedString()

        let finishPakeRequest = PakeRequest(
            authorization: nil,
            purpose: nil,
            sessionDuration: nil,
            requestData: authKE3
        )

        let innerRequest = try InnerRequest(type: .authenticateFinish, jsonData: finishPakeRequest)

        let outerRequest = OuterRequest(
            inner: innerRequest,
            sessionId: sessionId,
        )

        return FinishResult(outerRequest: outerRequest, sessionKey: clientFinish.sessionKey, exportKey: clientFinish.exportKey)
    }

    /// Starts OPAQUE PIN change (session required).
    ///
    /// Uses the OPAQUE registration flow with the new PIN. Both ``changePinStart(newPassword:)``
    /// and ``changePinFinish(start:password:credentialResponse:clientIdentifier:serverIdentifier:)``
    /// require an active session (call after ``authenticateFinish(clientRegistration:password:credentialResponse:context:clientIdentifier:serverIdentifier:sessionId:)``).
    ///
    /// - Parameter newPassword: Stretched new PIN from ``PINStretch/stretchPin(_:)``.
    /// - Returns: ``RegistrationStartResult`` with outer request and client state.
    /// - Throws: ``OpaqueClientError`` if OPAQUE operation fails.
    static func changePinStart(newPassword: StretchedPIN) throws -> RegistrationStartResult {
        let clientStart = try OpaqueClient.registrationStart(password: newPassword.data)
        let regKE1 = clientStart.registrationRequest.base64EncodedString()

        let startPakeRequest = PakeRequest(
            authorization: nil,
            purpose: nil,
            sessionDuration: nil,
            requestData: regKE1
        )

        let innerRequest = try InnerRequest(type: .changePinStart, jsonData: startPakeRequest)
        let outerRequest = OuterRequest(inner: innerRequest)

        return RegistrationStartResult(outerRequest: outerRequest, clientRegistration: clientStart.clientRegistration, authorization: nil)
    }

    /// Finishes OPAQUE PIN change (session required).
    ///
    /// - Parameters:
    ///   - start: Result from ``changePinStart(newPassword:)``.
    ///   - password: Same new PIN used in ``changePinStart(newPassword:)``.
    ///   - credentialResponse: Server's response from ``PakeResponse/responseData``.
    ///   - clientIdentifier: Client identifier (same as used in original registration).
    ///   - serverIdentifier: Server identifier (from ``ServerParameters/opaqueServerIdentifier``).
    /// - Returns: ``OuterRequest`` ready to sign and send. Server destroys session after this.
    /// - Throws: ``OpaqueClientError`` if OPAQUE operation fails.
    static func changePinFinish(
        start: RegistrationStartResult,
        password: StretchedPIN,
        credentialResponse: Data,
        clientIdentifier: Data,
        serverIdentifier: Data
    ) throws -> OuterRequest {
        let clientFinish = try OpaqueClient.registrationFinish(
            clientRegistration: start.clientRegistration,
            password: password.data,
            registrationResponse: credentialResponse,
            clientIdentifier: clientIdentifier,
            serverIdentifier: serverIdentifier
        )

        let regKE3 = clientFinish.registrationUpload.base64EncodedString()

        let finishPakeRequest = PakeRequest(
            authorization: nil,
            purpose: nil,
            sessionDuration: nil,
            requestData: regKE3
        )

        let innerRequest = try InnerRequest(type: .changePinFinish, jsonData: finishPakeRequest)
        return OuterRequest(inner: innerRequest)
    }

    /// Requests HSM to generate new P-256 key.
    ///
    /// Requires session mode (call ``ProtocolSession/enterSession(sessionId:sessionKey:)`` first).
    ///
    /// - Returns: ``OuterRequest`` ready to sign and send. Response will be ``HsmCreateKeyResponse``.
    /// - Throws: Encoding errors.
    public static func hsmGenerateKey() throws -> OuterRequest {
        let innerRequest = try InnerRequest(type: .hsmGenerateKey,
                                            jsonData: ["curve": "P-256"])

        let outerRequest = OuterRequest(
            inner: innerRequest,
        )

        return outerRequest
    }

    /// Requests HSM to list all keys.
    ///
    /// Requires session mode.
    ///
    /// - Returns: ``OuterRequest`` ready to sign and send. Response will be ``HsmListResponse``.
    /// - Throws: Encoding errors.
    public static func hsmListKeys() throws -> OuterRequest {
        let innerRequest = try InnerRequest(type: .hsmListKeys,
                                            jsonData: ["curve": [String]()]
        )

        let outerRequest = OuterRequest(
            inner: innerRequest,
        )

        return outerRequest
    }

    /// Requests HSM to sign a SHA-256 digest with specified key.
    ///
    /// Requires session mode. The `message` parameter must be a SHA-256 digest (32 bytes).
    /// Prefer ``BFFHttpClient/sign(hsmKeyId:data:)``, which hashes automatically.
    ///
    /// - Parameters:
    ///   - hsmKid: HSM key ID (from ``HsmCreateKeyResponse/public_key`` `kid` or ``HsmKeyInfo/kid``).
    ///   - message: SHA-256 digest to sign (32 bytes).
    /// - Returns: ``OuterRequest`` ready to sign and send. Response will be ``SignatureResponse``.
    /// - Throws: Encoding errors.
    public static func hsmSign(hsmKid: String, message: Data) throws -> OuterRequest {
        let innerObj = [
            "hsm_kid": hsmKid,
            "message": message.base64EncodedString()
        ]

        let innerRequest = try InnerRequest(type: .hsmSign,
                                            jsonData: innerObj)

        let outerRequest = OuterRequest(
            inner: innerRequest,
        )

        return outerRequest
    }

    /// Requests HSM to delete the specified key.
    ///
    /// - Parameter hsmKid: HSM key ID to delete.
    /// - Returns: ``OuterRequest`` ready to sign and send.
    /// - Throws: Encoding errors.
    public static func hsmDeleteKey(hsmKid: String) throws -> OuterRequest {
        let innerRequest = try InnerRequest(type: .hsmDeleteKey, jsonData: ["hsm_kid": hsmKid])
        let outerRequest = OuterRequest(inner: innerRequest)
        return outerRequest
    }
}
