//
//  OpaqueClient.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-15.
//

import Foundation
import OSLog

/// OPAQUE client errors.
public enum OpaqueClientError: Error {
    case clientStartFailure(code: Int32)
    case missingClientStartOutputs
    case clientFinishFailure(code: Int32)
    case missingClientFinishOutputs
    case registrationStartFailure(code: Int32)
    case missingRegistrationStartOutputs
    case registrationFinishFailure(code: Int32)
    case missingRegistrationFinishOutputs
}

/// OPAQUE PAKE client (Rust FFI wrapper).
///
/// Minimal Swift wrapper for Rust OPAQUE implementation (`OpaqueKeUniffi.xcframework`).
/// See [IRTF CFRG OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/) for protocol details.
///
/// **Note:** Most code should use ``ProtocolRequest`` helpers instead of calling ``OpaqueClient`` directly.
public struct OpaqueClient {

    /// Starts OPAQUE authentication.
    ///
    /// - Parameter password: Stretched PIN from ``PINStretch/stretchPin(_:)``.
    /// - Returns: Client start result with credential request and state.
    /// - Throws: ``OpaqueClientError`` if operation fails.
    static public func authenticateStart(password: Data) throws -> ClientLoginStartResult {

        return try clientLoginStart(password: password)

    }

    /// Completes the client authentication process using the server's credential response.
    /// - Parameters:
    ///   - clientRegistration: The client state from `authenticateStart`.
    ///   - password: The password as data bytes.
    ///   - credentialResponse: The server's credential response data.
    /// - Returns: A tuple containing the credential finalisation data and the session key.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func authenticateFinish(clientRegistration: Data, password: Data, credentialResponse: Data,
                                          context: Data, clientIdentifier: Data, serverIdentifier: Data) throws -> ClientLoginFinishResult {

        return try clientLoginFinish(credentialResponse: credentialResponse,
                                     clientRegistration: clientRegistration,
                                     password: password,
                                     context: context,
                                     clientIdentifier: clientIdentifier,
                                     serverIdentifier: serverIdentifier)
    }

    /// Starts the client registration process.
    /// - Parameter password: The password as data bytes.
    /// - Returns: A tuple containing the registration request data and a client registration handle for the next step.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func registrationStart(password: Data) throws -> ClientRegistrationStartResult {

        return try clientRegistrationStart(password: password)
    }

    /// Completes the client registration process using the server's registration response.
    /// - Parameters:
    ///   - clientRegistrationHandle: The client registration handle from `clientRegistrationStart`.
    ///   - password: The password as data bytes.
    ///   - registrationResponse: The server's registration response data.
    /// - Returns: A tuple containing the registration upload data to send to the server and the export key.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func registrationFinish(clientRegistration: Data,
                                          password: Data,
                                          registrationResponse: Data,
                                          clientIdentifier: Data,
                                          serverIdentifier: Data) throws -> ClientRegistrationFinishResult {

        return try clientRegistrationFinish(password: password,
                                            clientRegistration: clientRegistration,
                                            registrationResponse: registrationResponse,
                                            clientIdentifier: clientIdentifier,
                                            serverIdentifier: serverIdentifier)
    }
}
