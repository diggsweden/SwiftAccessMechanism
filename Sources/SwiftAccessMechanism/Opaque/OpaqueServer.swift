//
//  OpaqueServer.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-20.
//

import Foundation
import OpaqueKE

// Error types for the Opaque server
public enum OpaqueServerError: Error {
    case serverRegistrationStartFailure(code: Int32)
    case missingRegistrationResponseHandle
    case serverRegistrationFinishFailure(code: Int32)
    case missingPasswordFileHandle
    case serverLoginStartFailure(code: Int32)
    case missingOutputBuffers
    case serverLoginFinishFailure(code: Int32)
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
    static public func registrationStart(serverSetupHandle: ServerSetupHandle, registrationRequest: Data, clientID: Data) throws -> Data {
        var outRegistrationResponseHandle: UnsafeMutableRawPointer?

        // create buffer handles for inputs
        let requestBuffer = OpaqueKEBuffer(data: registrationRequest)
        let clientIdBuffer = OpaqueKEBuffer(data: clientID)

        let returnCode = serverSetupHandle.value.withRawHandle { setupHandle in
            requestBuffer.withRawHandle { reqHandle in
                clientIdBuffer.withRawHandle { cidHandle in
                    opaque_ke_server_registration_start(setupHandle, reqHandle, cidHandle,
                                                        &outRegistrationResponseHandle
                    )
                }
            }
        }

        guard returnCode == 0 else {
            throw OpaqueServerError.serverRegistrationStartFailure(code: returnCode)
        }

        guard let respBuf = OpaqueKEBuffer(handle: outRegistrationResponseHandle),
              let registrationResponse = respBuf.data
        else {
            throw OpaqueServerError.missingRegistrationResponseHandle
        }

        return registrationResponse
    }

    /// Wrapper for `opaque_ke_server_registration_finish`
    /// - Parameters:
    ///   - serverRegistrationHandle: The server registration handle.
    ///   - registrationUpload: The registration upload as `Data`.
    /// - Returns: The password file as `Data`.
    /// - Throws: An `OpaqueServerError` if the operation fails.
    static public func registrationFinish(registrationUpload: Data) throws -> Data {
        var outPasswordFileHandle: UnsafeMutableRawPointer?

        let uploadBuffer = OpaqueKEBuffer(data: registrationUpload)

        let returnCode = uploadBuffer.withRawHandle { uploadHandle in
            opaque_ke_server_registration_finish(uploadHandle, &outPasswordFileHandle)
        }

        guard returnCode == 0 else {
            throw OpaqueServerError.serverRegistrationFinishFailure(code: returnCode)
        }

        guard let passwordFileBuffer = OpaqueKEBuffer(handle: outPasswordFileHandle),
              let passwordFile = passwordFileBuffer.data
        else {
            throw OpaqueServerError.missingPasswordFileHandle
        }

        return passwordFile
    }

    /// Wrapper for `opaque_ke_server_login_start`
    ///
    /// Initiates the server-side login process by processing the client's login request.
    /// This is the first step in the OPAQUE login flow from the server's perspective.
    ///
    /// - Parameters:
    ///   - serverSetupHandle: The server setup handle containing the server's configuration and keys.
    ///   - clientRequest: The client's login request data (KE1 message).
    ///   - clientID: The client identifier as `Data`.
    ///   - passwordFile: Optional password file data from a previous registration. If `nil`, the server will attempt login without a stored password file.
    /// - Returns: A tuple containing the credential response data to send back to the client and the server login state data for use in `loginFinish()`.
    /// - Throws: An `OpaqueServerError` if the operation fails.
    static public func loginStart(
        serverSetupHandle: ServerSetupHandle,
        clientRequest: Data,
        clientID: Data,
        passwordFile: Data? = nil
    ) throws -> (credentialResponse: Data, serverLogin: Data) {
        var outCredHandle: UnsafeMutableRawPointer? = nil
        var outLoginHandle: UnsafeMutableRawPointer? = nil

        let requestBuffer = OpaqueKEBuffer(data: clientRequest)
        let clientIdBuffer = OpaqueKEBuffer(data: clientID)
        let passwordFileBuffer = OpaqueKEBuffer(data: passwordFile)

        let returnCode = serverSetupHandle.value.withRawHandle { setupHandle in
            requestBuffer.withRawHandle { reqHandle in
                clientIdBuffer.withRawHandle { clientIDHandle in
                    passwordFileBuffer.withRawHandleOrNull { passwordFileHandle in
                        opaque_ke_server_login_start(setupHandle, passwordFileHandle, reqHandle, clientIDHandle,
                                                     &outCredHandle, &outLoginHandle)
                    }
                }
            }
        }

        guard returnCode == 0 else {
            throw OpaqueServerError.serverLoginStartFailure(code: returnCode)
        }

        guard let responseBuffer = OpaqueKEBuffer(handle: outCredHandle),
              let loginBuffer = OpaqueKEBuffer(handle: outLoginHandle),
              let credentialResponse = responseBuffer.data,
              let serverLogin = loginBuffer.data
        else {
            throw OpaqueServerError.missingOutputBuffers
        }

        return (credentialResponse, serverLogin)
    }

    /// Wrapper for `opaque_ke_server_login_finish`.
    ///
    /// - Parameters:
    ///   - serverLogin: The serverLogin blob previously returned by `serverLoginStart`.
    ///   - clientFinalization: The client's finalisation bytes produced by the client (KE3/Finalisation).
    /// - Returns: A tuple with the server's session key as `Data` on success.
    /// - Throws: An `OpaqueServerError` when the underlying call returns a non-zero code or outputs are missing.
    static public func loginFinish(serverLogin: Data, clientFinalization: Data) throws -> (sessionKey: Data, _unused: Data?) {
        var outSessionHandle: UnsafeMutableRawPointer? = nil

        let loginBuffer = OpaqueKEBuffer(data: serverLogin)
        let finalBuffer = OpaqueKEBuffer(data: clientFinalization)

        let returnCode = loginBuffer.withRawHandle { loginHandle in
            finalBuffer.withRawHandle { finalHandle in
                opaque_ke_server_login_finish(loginHandle, finalHandle, &outSessionHandle)
            }
        }

        guard returnCode == 0 else {
            throw OpaqueServerError.serverLoginFinishFailure(code: returnCode)
        }

        guard let sessionBuf = OpaqueKEBuffer(handle: outSessionHandle),
              let sessionKey = sessionBuf.data
        else {
            throw OpaqueServerError.missingSessionKeyOutput
        }

        // Return a tuple for consistency with the other functions in the login flow.
        // Swift won't let us create a tuple with only one element though.
        return (sessionKey: sessionKey, _unused: nil)
    }

}
