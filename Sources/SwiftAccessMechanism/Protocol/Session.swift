//
//  Session.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2026-02-05.
//

import Foundation
import JOSESwift

/// Encryption mode for Protocol layer.
enum EncryptionType: String, Codable {
    /// Device mode: ECDH-ES encryption using server public key (before OPAQUE authentication).
    case device = "device"
    /// Session mode: Direct symmetric encryption using OPAQUE session key (after authentication).
    case session = "session"
}

struct ProtocolEncryption {
    fileprivate let encrypter: Encrypter
    fileprivate let decrypter: Decrypter
    fileprivate let header: JWEHeader
}

/// Manages signing/encryption state for JWS/JWE message wrapping.
///
/// `ProtocolSession` maintains two encryption modes:
/// - **Device mode** (initial): ECDH-ES encryption using server's public key
/// - **Session mode** (after OPAQUE): Direct symmetric encryption using session key
///
/// ## Example
///
/// ```swift
/// // Initialize in device mode
/// let session = try ProtocolSession(
///     clientPrivateKey: clientKey,
///     serverPublicKey: serverParams.serverPublicKey
/// )
///
/// // After OPAQUE authentication, switch to session mode
/// session.enterSession(sessionId: "abc-123", sessionKey: sessionKeyData)
/// ```
///
/// See ``enterSession(sessionId:sessionKey:)`` for mode transition details.
struct ProtocolSession {

    /// Errors thrown by `ProtocolSession`.
    enum Errors: Error {
        case signerCreationFailed
        case serverKeyParseError
        case clientKeyParseError
        case invalidSessionKey
        case failedToCreateDirectDecrypter
    }

    fileprivate let clientPrivateKey: SecKey
    fileprivate let serverPublicKey: SecKey

    fileprivate var encryption: ProtocolEncryption
    let signer: Signer  // Sign outer JWS:es using client private key
    let verifier: Verifier  // Verify outer JWS:es signed by server public key

    /// Current encryption mode (`.device` or `.session`).
    var mode: EncryptionType = .device

    /// Session identifier (set after calling ``enterSession(sessionId:sessionKey:)``).
    var sessionId: String? = nil
    let deviceKid: String

    var encrypter: Encrypter {
        return self.encryption.encrypter
    }

    var decrypter: Decrypter {
        return self.encryption.decrypter
    }

    var header: JWEHeader {
        return self.encryption.header
    }

    /// Initializes session in device mode with ECDH-ES encryption.
    ///
    /// - Parameters:
    ///   - clientPrivateKey: P-256 private key for signing outer JWS layer.
    ///   - serverPublicKey: Server's P-256 public key for ECDH-ES encryption in device mode.
    ///
    /// - Throws: ``Errors/signerCreationFailed``, ``Errors/serverKeyParseError``, or ``Errors/clientKeyParseError`` if key initialization fails.
    init(clientPrivateKey: SecKey, serverPublicKey: SecKey) throws {
        self.clientPrivateKey = clientPrivateKey
        self.serverPublicKey = serverPublicKey

        /// Signer/verifier for the outer request/response
        guard let signer = Signer(signatureAlgorithm: .ES256, key: clientPrivateKey) else {
            throw Errors.signerCreationFailed
        }
        self.signer = signer

        guard let verifier = Verifier(signatureAlgorithm: .ES256, key: serverPublicKey) else {
            throw Errors.serverKeyParseError
        }
        self.verifier = verifier

        self.encryption = try ProtocolSession.initDeviceEncryption(clientPrivateKey: clientPrivateKey, serverPublicKey: serverPublicKey)

        self.deviceKid = try computeJwkThumbprint(privateKey: clientPrivateKey)
    }

    fileprivate static func initDeviceEncryption(clientPrivateKey: SecKey, serverPublicKey: SecKey) throws -> ProtocolEncryption {
        /// Encrypter/decrypter for the inner request/response
        /// NOTE: This starts out in "device" encryption mode. After a successful authentication, the enterSession() function below takes us to "session" encryption mode.
        let josePublicKey = try ECPublicKey(publicKey: serverPublicKey)
        guard let encrypter = Encrypter(keyManagementAlgorithm: .ECDH_ES,
                                        contentEncryptionAlgorithm: .A256GCM,
                                        encryptionKey: josePublicKey) else {
            throw Errors.serverKeyParseError
        }

        let josePrivateKey = try ECPrivateKey(privateKey: clientPrivateKey)
        guard let decrypter = Decrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A256GCM, decryptionKey: josePrivateKey) else {
            throw Errors.clientKeyParseError
        }

        var header = JWEHeader(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A256GCM)
        header.kid = "device"

        return ProtocolEncryption(encrypter: encrypter, decrypter: decrypter, header: header)
    }

    /// Switches session from device mode to session mode using OPAQUE session key.
    ///
    /// Call this after successful OPAQUE authentication to enable HSM operations.
    /// Replaces ECDH-ES encryption with direct symmetric encryption using `sessionKey`.
    ///
    /// - Parameters:
    ///   - sessionId: Session identifier from OPAQUE authentication.
    ///   - sessionKey: 32-byte symmetric key from OPAQUE (from `ClientLoginFinishResult.sessionKey`).
    ///
    /// - Throws: ``Errors/invalidSessionKey`` or ``Errors/failedToCreateDirectDecrypter`` if session key is invalid.
    mutating func enterSession(sessionId: String, sessionKey: Data) throws {
        guard let encrypter = Encrypter(keyManagementAlgorithm: .direct,
                                        contentEncryptionAlgorithm: .A256GCM,
                                        encryptionKey: sessionKey) else {
            throw Errors.invalidSessionKey
        }

        guard let decrypter = Decrypter(keyManagementAlgorithm: .direct,
                                        contentEncryptionAlgorithm: .A256GCM,
                                        decryptionKey: sessionKey) else {
            throw Errors.failedToCreateDirectDecrypter
        }

        var header = JWEHeader(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256GCM)
        header.kid = "session"

        self.sessionId = sessionId
        self.encryption = ProtocolEncryption(encrypter: encrypter, decrypter: decrypter, header: header)
        self.mode = .session
    }
}
