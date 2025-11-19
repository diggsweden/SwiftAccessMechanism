//
//  OpaqueExample.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-11.
//

import Foundation
import OpaqueKE

// Error types for the Opaque example
public enum OpaqueExampleError: Error {
    case serverSetupCreationFailed
}

public struct OpaqueExample {

    /// Set up a demo registration flow and return the server setup handle and password file needed for later login.
    /// - Parameter password: The password as data bytes.
    /// - Returns: A tuple containing the server setup handle, password file, and optional client export key.
    /// - Throws: An `OpaqueExampleError` if the operation fails.
    static public func setUp(password: Data) throws -> (serverSetupHandle: ServerSetupHandle, passwordFile: Data, clientExportKey: Data?) {
        guard let setupRaw = opaque_ke_server_setup_new(nil) else {
            throw OpaqueExampleError.serverSetupCreationFailed
        }
        let setupHandle = ServerSetupHandle(setupRaw)

        // Client: start registration -> get registration request data and client registration handle
        let (registrationRequest, clientRegHandle) = try OpaqueClient.registrationStart(password: password)

        // Server: process registration request and return registration response
        let registrationResponse = try OpaqueServer.registrationStart(serverSetupHandle: setupHandle, registrationRequest: registrationRequest, clientID: Data())

        // Client: finish registration using registration response -> get upload data and export key
        let (uploadData, exportKey) = try OpaqueClient.registrationFinish(clientRegistrationHandle: clientRegHandle, password: password, registrationResponse: registrationResponse)

        // Server: finish registration using upload data -> create password file
        let passwordFile = try OpaqueServer.registrationFinish(registrationUpload: uploadData)

        // Return setup handle (needed for login), password file (server stores this), and export key (client can use for additional cryptographic operations)
        return (serverSetupHandle: setupHandle, passwordFile: passwordFile, clientExportKey: exportKey)
    }

    /// doLogin runs a full client+server login flow using the previously returned setup handle and password file.
    /// - Parameters:
    ///   - setupHandle: The `ServerSetupHandle` returned from `setUp()`.
    ///   - password: The user's password as data bytes.
    ///   - passwordFile: The server's password file produced by registration.
    /// - Returns: A tuple containing the client's session key and the server's session key.
    /// - Throws: An `OpaqueClientError` or `OpaqueServerError` if any operation fails.
    static public func doLogin(setupHandle: ServerSetupHandle, password: Data, passwordFile: Data) throws -> (clientSessionKey: Data, serverSessionKey: Data) {
        // Step 1: Client starts login -> generate credential request and client login handle
        //let (credReq, clientLoginHandle) = try OpaqueClient.loginStart(password: password)
        let clientStart = try OpaqueClient.loginStart(password: password)

        // the client request is transmitted to the server
        let clientRequest = clientStart.credentialRequest

        // Step 2: Server processes credential request -> produce credential response and server login data
        let serverData = try OpaqueServer.loginStart(serverSetupHandle: setupHandle,
                                                     clientRequest: clientRequest,
                                                     clientID: Data(),
                                                     passwordFile: passwordFile)

        // the credential response is transmitted back to the server
        let credentialResponse = serverData.credentialResponse

        // Step 3: Client finishes login using credential response -> obtain finalisation data and session key
        let clientFinish = try OpaqueClient.loginFinish(clientLoginHandle: clientStart.clientLoginHandle,
                                                        password: password,
                                                        credentialResponse: credentialResponse)

        // the client's credential finalisation data is transmitted to the server
        let credentialFinalization = clientFinish.credentialFinalization

        // Step 4: Server finishes login using client finalisation -> obtain server session key
        let serverFinish = try OpaqueServer.loginFinish(serverLogin: serverData.serverLogin,
                                                        clientFinalization: credentialFinalization)

        // Return both session keys for verification that they match
        return (clientSessionKey: clientFinish.sessionKey, serverSessionKey: serverFinish.sessionKey)
    }
}
