// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  Inner.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2026-02-04.
//

import Foundation
import JOSESwift
import OSLog

/// Request type identifier for inner (encrypted) layer.
///
/// Maps to server-side operations. All operations available, though only subset commonly used:
/// - OPAQUE: ``authenticateStart``, ``authenticateFinish``, ``registerStart``, ``registerFinish``
/// - HSM: ``hsmGenerateKey``, ``hsmListKeys``, ``hsmSign``, ``hsmDeleteKey``, ``hsmEcdh``
/// - Session: ``endSession``, ``pinChange``
/// - Storage: ``store``, ``retrieve``
/// - Logging: ``log``, ``getLog``
/// - Info: ``info``
enum InnerRequestId: String, Codable {
    case authenticateStart = "authenticate_start"
    case authenticateFinish = "authenticate_finish"
    case registerStart = "register_start"
    case registerFinish = "register_finish"
    case pinChange = "pin_change"
    case hsmSign = "hsm_sign"
    case hsmEcdh = "hsm_ecdh"
    case hsmGenerateKey = "hsm_generate_key"
    case hsmDeleteKey = "hsm_delete_key"
    case hsmListKeys = "hsm_list_keys"
    case endSession = "session_end"
    case store
    case retrieve
    case log
    case getLog = "get_log"
    case info
}

/// Client request inner layer (JWE encrypted).
///
/// Contains plaintext request data that will be encrypted before signing outer layer.
///
/// ## Example
///
/// ```swift
/// let innerRequest = try InnerRequest(
///     type: .hsmGenerateKey,
///     jsonData: ["curve": "P-256"]
/// )
/// let jwe = try innerRequest.toJwe(session: session)
/// ```
struct InnerRequest: Codable {
    let version: Int32 = 1

    /// Request type (determines server-side handler).
    let type: InnerRequestId

    /// Request counter (for replay protection, typically 1).
    var requestCounter: Int32

    /// JSON-encoded request data (varies by type).
    let data: String

    enum CodingKeys: String, CodingKey {
        case version, type, data
        case requestCounter = "request_counter"
    }

    enum Errors: Error {
        case invalidResponseDataEncoding
    }

    /// Encrypts inner request to JWE.
    ///
    /// - Parameter session: Protocol session (mode determines ECDH-ES vs Direct encryption).
    /// - Returns: JWE compact serialization.
    /// - Throws: Encryption errors.
    func toJwe(session: ProtocolSession) throws -> String {
        let payloadData = try JSONEncoder().encode(self)

        let jwe = try JWE(header: session.header,
                          payload: Payload(payloadData),
                          encrypter: session.encrypter)
        return jwe.compactSerializedString
    }
}

extension InnerRequest {
    /// Convenience initializer for typed request data.
    ///
    /// - Parameters:
    ///   - type: Request type identifier.
    ///   - jsonData: Encodable request data (will be JSON-encoded to `data` field).
    ///   - requestCounter: Request counter (default 1).
    /// - Throws: Encoding errors.
    init<T: Encodable>(type: InnerRequestId, jsonData: T, requestCounter: Int32 = 1) throws {
        let dataBytes = try JSONEncoder().encode(jsonData)
        guard let dataString = String(data: dataBytes, encoding: .utf8) else {
            throw Errors.invalidResponseDataEncoding
        }
        self.init(type: type, requestCounter: requestCounter, data: dataString)
    }
}

/// Server response inner layer (JWE encrypted, decrypted by ``OuterResponse``).
///
/// Contains plaintext response data after decryption.
///
/// ## Example
///
/// ```swift
/// let innerResponse: InnerResponse = outerResponse.innerResponse
/// let payload: HsmCreateKeyResponse = try innerResponse.decodePayload(HsmCreateKeyResponse.self)
/// ```
public struct InnerResponse: Codable {
    /// Response status.
    public enum Status: String, Codable, Sendable {
        case ok = "OK"
        case error = "ERROR"
    }

    /// Protocol version.
    public let version: Int32

    /// JSON-encoded response data (decode with ``decodePayload(_:)``).
    public let data: String?

    /// Session expiration time (if applicable).
    public let expiresIn: String?

    /// Response status (OK or ERROR).
    public let status: Status

    enum CodingKeys: String, CodingKey {
        case version, data
        case expiresIn = "expires_in"
        case status
    }

    /// Decodes response data to typed model.
    ///
    /// - Parameter type: Expected response type (e.g., `PakeResponse.self`, `HsmCreateKeyResponse.self`).
    /// - Returns: Decoded response object.
    /// - Throws: Decoding errors.
    func decodePayload<T: Decodable>(_ type: T.Type) throws -> T {
        let payload = self.data?.data(using: .utf8) ?? Data()
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


