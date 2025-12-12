//
//  OpaqueClient.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-15.
//

import Foundation
import OSLog

// Error types for the Opaque client
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

public struct OpaqueClient {

    /// Starts the client login process by generating a credential request.
    /// - Parameter password: The password as a string.
    /// - Returns: A tuple containing the credential request data and a client login handle for the next step.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func loginStart(password: Data) throws -> ClientLoginStartResult {

        return try clientLoginStart(password: password)

    }

    /// Completes the client login process using the server's credential response.
    /// - Parameters:
    ///   - clientLoginHandle: The client login handle from `clientStart`.
    ///   - password: The password as data bytes.
    ///   - credentialResponse: The server's credential response data.
    /// - Returns: A tuple containing the credential finalisation data and the session key.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func loginFinish(clientRegistration: Data, password: Data, credentialResponse: Data,
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
