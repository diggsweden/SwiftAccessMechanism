// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  Outer.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2026-02-04.
//

import Foundation
import JOSESwift
import OSLog

/// Server response outer layer (JWS signed).
///
/// Decrypts and validates server's JWS response, extracting ``InnerResponse``.
///
/// ## Example
///
/// ```swift
/// let outerResponse = try OuterResponse(jwsString: serverJWS, session: session)
/// let innerResponse = outerResponse.innerResponse
/// let payload: PakeResponse = try innerResponse.decodePayload(PakeResponse.self)
/// ```
public struct OuterResponse {
    /// Protocol version from server.
    public let version: Int32

    /// Session ID (present in session mode responses).
    public let sessionId: String?

    /// Decrypted inner response (JWE layer).
    public let innerResponse: InnerResponse

    fileprivate struct DTO: Codable {
        let version: Int32
        let innerJwe: String?
        let sessionId: String?
        let status: InnerResponse.Status?
        let errorMessage: String?

        enum CodingKeys: String, CodingKey {
            case version
            case innerJwe = "inner_jwe"
            case sessionId = "session_id"
            case status
            case errorMessage = "error_message"
        }
    }

    enum Error: Swift.Error {
        case invalidSignature
        case decodingError(Swift.Error)
        case unexpectedEncryption(String)
    }

    /// Parses and validates JWS response from server.
    ///
    /// - Parameters:
    ///   - jwsString: JWS compact serialization from server.
    ///   - session: Protocol session for signature verification and decryption.
    /// - Throws: ``Error/invalidSignature`` if JWS signature invalid, ``Error/decodingError(_:)`` if payload malformed, or decryption errors.
    init(jwsString: String, session: ProtocolSession) throws {
        let jws = try JWS(compactSerialization: jwsString)
        guard jws.isValid(for: session.verifier) else {
            throw Error.invalidSignature
        }

        let payloadData = jws.payload.data()

        let dto: DTO
        do {
            dto = try JSONDecoder().decode(DTO.self, from: payloadData)
        } catch {
            throw Error.decodingError(error)
        }

        self.version = dto.version
        self.sessionId = dto.sessionId

        if dto.status == .error {
            throw ServerError(message: dto.errorMessage ?? "Unknown outer error")
        }

        guard let innerJwe = dto.innerJwe else {
            throw ServerError(message: "Missing inner_jwe in response")
        }

        let decryptedData: Data
        do {
            decryptedData = try session.decryptInnerJwe(innerJwe)
        } catch {
            Logger.api.error("Failed decrypting inner JWE: \(error)")
            Logger.api.debug("Tried decrypting using mode '\(session.mode.rawValue)'")
            throw error
        }

        self.innerResponse = try JSONDecoder().decode(InnerResponse.self, from: decryptedData)
    }
}


/// Client request outer layer (JWS signed).
///
/// Wraps ``InnerRequest`` (JWE encrypted) in signed JWS envelope.
///
/// ## Example
///
/// ```swift
/// let innerRequest = try InnerRequest(type: .hsmGenerateKey, jsonData: ["curve": "P-256"])
/// let outerRequest = OuterRequest(inner: innerRequest, sessionId: session.sessionId)
/// let jws = try outerRequest.toJWS(signer: signer, session: session)
/// // Send JWS string to server
/// ```
struct OuterRequest {
    let version: Int32 = 1
    // Protocol-level context constant
    let context: String = "hsm"

    /// Session ID (nil in device mode, required in session mode).
    let sessionId: String?

    /// Inner request (will be encrypted to JWE).
    let inner: InnerRequest

    fileprivate struct DTO: Codable {
        let version: Int32
        let context: String
        let nonce: String
        let sessionId: String?
        let innerJwe: String

        enum CodingKeys: String, CodingKey {
            case version
            case context
            case nonce
            case sessionId = "session_id"
            case innerJwe = "inner_jwe"
        }
    }

    init(inner: InnerRequest) {
        self.inner = inner
        self.sessionId = nil
    }

    init(inner: InnerRequest, sessionId: String?) {
        self.inner = inner
        self.sessionId = sessionId
    }

    /// Encrypts inner request and signs outer request to JWS.
    ///
    /// - Parameters:
    ///   - signer: Signer created from client private key (``ProtocolSession/signer``).
    ///   - session: Protocol session for encryption (mode determines ECDH-ES vs Direct).
    /// - Returns: JWS compact serialization ready to send to server.
    /// - Throws: Encryption or signing errors.
    func toJWS(signer: Signer, session: ProtocolSession) throws -> String {
        let sessionId = self.sessionId ?? session.sessionId
        let innerJwe = try inner.toJwe(session: session)
        let dto = DTO(version: self.version, context: self.context, nonce: UUID().uuidString, sessionId: sessionId, innerJwe: innerJwe)

        let requestData = try JSONEncoder().encode(dto)
        let payload = Payload(requestData)

        var header = JWSHeader(algorithm: .ES256)
        header.typ = "JOSE"
        header.kid = session.deviceKid

        let jws = try JWS(header: header, payload: payload, signer: signer)
        return jws.compactSerializedString
    }
}
