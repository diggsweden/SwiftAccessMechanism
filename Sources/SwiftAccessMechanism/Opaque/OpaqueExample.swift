//
//  OpaqueExample.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-11.
//

import Foundation

// Error types for the Opaque example
public enum OpaqueExampleError: Error {
    case serverSetupCreationFailed
}

public struct OpaqueExample {

    /// Set up a demo registration flow and return the server setup handle and password file needed for later login.
    /// - Parameter password: The password as data bytes.
    /// - Returns: A tuple containing the server setup handle, password file, and optional client export key.
    /// - Throws: An `OpaqueExampleError` if the operation fails.
    static public func setUp(password: Data) throws -> (serverSetupHandle: Data, passwordFile: Data, clientExportKey: Data) {
        let serverSetup = serverSetup()

        // Client: start registration -> get registration request data and client registration handle
        let clientRegistrationStartResult = try OpaqueClient.registrationStart(password: password)

        // Server: process registration request and return registration response
        let registrationResponse = try OpaqueServer.registrationStart(serverSetup: serverSetup,
                                                                      registrationRequest: clientRegistrationStartResult.registrationRequest,
                                                                      clientID: Data())

        // Client: finish registration using registration response -> get upload data and export key
        let clientRegistrationFinishResult = try OpaqueClient.registrationFinish(clientRegistration: clientRegistrationStartResult.clientRegistration,
                                                                                 password: password,
                                                                                 registrationResponse: registrationResponse,
                                                                                 clientIdentifier: Data(),
                                                                                 serverIdentifier: Data())

        // Server: finish registration using upload data -> create password file
        let passwordFile = try OpaqueServer.registrationFinish(registrationUpload: clientRegistrationFinishResult.registrationUpload)

        // Return setup handle (needed for login), password file (server stores this), and export key (client can use for additional cryptographic operations)
        return (serverSetupHandle: serverSetup, passwordFile: passwordFile, clientExportKey: clientRegistrationFinishResult.exportKey)
    }

    /// doLogin runs a full client+server login flow using the previously returned setup handle and password file.
    /// - Parameters:
    ///   - setupHandle: The `ServerSetupHandle` returned from `setUp()`.
    ///   - password: The user's password as data bytes.
    ///   - passwordFile: The server's password file produced by registration.
    /// - Returns: A tuple containing the client's session key and the server's session key.
    /// - Throws: An `OpaqueClientError` or `OpaqueServerError` if any operation fails.
    static public func doLogin(setupHandle: Data, password: Data, passwordFile: Data) throws -> (clientSessionKey: Data, serverSessionKey: Data) {
        let context = Data()
        let clientIdentifier = Data()
        let serverIdentifier = Data()
        let serverSideClientId = Data()

        // Step 1: Client starts login -> generate credential request and client login handle
        //let (credReq, clientLoginHandle) = try OpaqueClient.loginStart(password: password)
        let clientStart = try OpaqueClient.loginStart(password: password)

        // the client request is transmitted to the server
        let clientRequest = clientStart.credentialRequest

        // Step 2: Server processes credential request -> produce credential response and server login data
        let serverData = try OpaqueServer.loginStart(serverSetup: setupHandle,
                                                     clientId: serverSideClientId,
                                                     clientRequest: clientRequest,
                                                     passwordFile: passwordFile,
                                                     context: context,
                                                     clientIdentifier: clientIdentifier,
                                                     serverIdentifier: serverIdentifier)

        // the credential response is transmitted back to the server
        let credentialResponse = serverData.credentialResponse

        // Step 3: Client finishes login using credential response -> obtain finalisation data and session key
        let clientFinish = try OpaqueClient.loginFinish(clientRegistration: clientStart.clientRegistration,
                                                        password: password,
                                                        credentialResponse: credentialResponse,
                                                        context: context,
                                                        clientIdentifier: clientIdentifier,
                                                        serverIdentifier: serverIdentifier)

        // the client's credential finalisation data is transmitted to the server
        let credentialFinalization = clientFinish.credentialFinalization

        // Step 4: Server finishes login using client finalisation -> obtain server session key
        let sessionKey = try OpaqueServer.loginFinish(serverLogin: serverData.serverLogin,
                                                      clientFinalization: credentialFinalization,
                                                      context: context,
                                                      clientIdentifier: clientIdentifier,
                                                      serverIdentifier: serverIdentifier)

        // Return both session keys for verification that they match
        return (clientSessionKey: clientFinish.sessionKey, serverSessionKey: sessionKey)
    }
}
