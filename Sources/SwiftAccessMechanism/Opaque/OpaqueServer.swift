// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  OpaqueServer.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-20.
//

import Foundation

// Error types for the Opaque server
public enum OpaqueServerError: Error {
    case serverRegistrationStartFailure(code: Int32)
    case missingRegistrationResponseHandle
    case serverRegistrationFinishFailure(code: Int32)
    case missingPasswordFileHandle
    case serverAuthenticateStartFailure(code: Int32)
    case missingOutputBuffers
    case serverAuthenticateFinishFailure(code: Int32)
    case missingSessionKeyOutput
}

public struct OpaqueServer {

    /// Wrapper for `opaque_ke_server_registration_start`
    /// - Parameters:
    ///   - serverSetupHandle: The server setup handle.
    ///   - registrationRequest: The registration request as `Data`.
    ///   - clientID: The client ID as `Data`.
    /// - Returns: The registration response data as `Data`.
    /// - Throws: An `OpaqueServerError` if the operation fails.
    static public func registrationStart(serverSetup: Data, registrationRequest: Data, clientID: Data) throws -> Data {

        return try serverRegistrationStart(serverSetup: serverSetup,
                                           registrationRequest: registrationRequest,
                                           clientId: clientID)
    }

    /// Wrapper for `opaque_ke_server_registration_finish`
    /// - Parameters:
    ///   - serverRegistrationHandle: The server registration handle.
    ///   - registrationUpload: The registration upload as `Data`.
    /// - Returns: The password file as `Data`.
    /// - Throws: An `OpaqueServerError` if the operation fails.
    static public func registrationFinish(registrationUpload: Data) throws -> Data {

        return try serverRegistrationFinish(registrationUpload: registrationUpload)
    }

    /// Wrapper for `opaque_ke_server_login_start`
    ///
    /// Initiates the server-side authentication by processing the client's request.
    /// This is the first step in the OPAQUE authentication flow from the server's perspective.
    ///
    /// - Parameters:
    ///   - serverSetupHandle: The server setup handle containing the server's configuration and keys.
    ///   - clientRequest: The client's authentication request data (KE1 message).
    ///   - passwordFile: Optional password file data from a previous registration. If `nil`, the server will attempt authentication without a stored password file.
    /// - Returns: A tuple containing the credential response data to send back to the client and the server state data for use in `authenticateFinish()`.
    /// - Throws: An `OpaqueServerError` if the operation fails.
    static public func authenticateStart(
        serverSetup: Data,
        clientId: Data,
        clientRequest: Data,
        passwordFile: Data? = nil,
        context: Data,
        clientIdentifier: Data,
        serverIdentifier: Data
    ) throws -> ServerLoginStartResult {

        return try serverLoginStart(serverSetup: serverSetup, passwordFile: passwordFile!, credentialRequest: clientRequest,
        clientId: clientId,
        context: context,
        clientIdentifier: clientIdentifier,
        serverIdentifier: serverIdentifier)
    }

    /// Wrapper for `opaque_ke_server_login_finish`.
    ///
    /// - Parameters:
    ///   - serverLogin: The serverLogin blob previously returned by `authenticateStart`.
    ///   - clientFinalization: The client's finalisation bytes produced by the client (KE3/Finalisation).
    /// - Returns: A tuple with the server's session key as `Data` on success.
    /// - Throws: An `OpaqueServerError` when the underlying call returns a non-zero code or outputs are missing.
    static public func authenticateFinish(serverLogin: Data, clientFinalization: Data,
                                   context: Data, clientIdentifier: Data, serverIdentifier: Data) throws -> Data {

        return try serverLoginFinish(serverLogin: serverLogin,
                                     credentialFinalization: clientFinalization,
                                     context: context,
                                     clientIdentifier: clientIdentifier,
                                     serverIdentifier: serverIdentifier)
    }

}
