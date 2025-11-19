//
//  OpaqueClient.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-15.
//

import Foundation
import OSLog
import OpaqueKE

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
    static public func loginStart(password: Data) throws -> (credentialRequest: Data, clientLoginHandle: ClientLoginHandle) {
        var outRequestHandle: UnsafeMutableRawPointer? = nil
        var outCLHandle: UnsafeMutableRawPointer? = nil

        let returnCode = OpaqueKEBuffer(data: password).withRawHandle { passwordHandle in
            opaque_ke_client_login_start(passwordHandle, &outRequestHandle, &outCLHandle)
        }

        if returnCode != 0 {
            throw OpaqueClientError.clientStartFailure(code: returnCode)
        }

        guard let requestBuffer = OpaqueKEBuffer(handle: outRequestHandle),
              let clientLoginHandle = OpaqueKEBuffer(handle: outCLHandle),
              let credReq = requestBuffer.data
        else {
            throw OpaqueClientError.missingClientStartOutputs
        }

        return (credReq, ClientLoginHandle(clientLoginHandle))
    }

    /// Completes the client login process using the server's credential response.
    /// - Parameters:
    ///   - clientLoginHandle: The client login handle from `clientStart`.
    ///   - password: The password as data bytes.
    ///   - credentialResponse: The server's credential response data.
    /// - Returns: A tuple containing the credential finalisation data and the session key.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func loginFinish(clientLoginHandle: ClientLoginHandle, password: Data, credentialResponse: Data) throws -> (credentialFinalization: Data, sessionKey: Data) {
        var outFinalHandle: UnsafeMutableRawPointer? = nil
        var outSessionHandle: UnsafeMutableRawPointer? = nil

        let responseBuffer = OpaqueKEBuffer(data: credentialResponse)
        let passwordBuffer = OpaqueKEBuffer(data: password)

        let returnCode = clientLoginHandle.value.withRawHandle { rawCL in
            passwordBuffer.withRawHandle { passwordHandle in
                responseBuffer.withRawHandle { responseHandle in
                    opaque_ke_client_login_finish(rawCL, passwordHandle, responseHandle, &outFinalHandle, &outSessionHandle)
                }
            }
        }

        if returnCode != 0 {
            throw OpaqueClientError.clientFinishFailure(code: returnCode)
        }

        guard let finalBuf = OpaqueKEBuffer(handle: outFinalHandle),
              let sessionBuf = OpaqueKEBuffer(handle: outSessionHandle),
              let finalData = finalBuf.data,
              let sessionKey = sessionBuf.data
        else {
            throw OpaqueClientError.missingClientFinishOutputs
        }

        return (finalData, sessionKey)
    }

    /// Starts the client registration process.
    /// - Parameter password: The password as data bytes.
    /// - Returns: A tuple containing the registration request data and a client registration handle for the next step.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func registrationStart(password: Data) throws -> (request: Data, clientRegistrationHandle: OpaqueKEBuffer) {
        var outRequestHandle: UnsafeMutableRawPointer?
        var outClientRegistrationHandle: UnsafeMutableRawPointer?

        // create a password buffer handle using OpaqueKEBuffer
        let passwordBuffer = OpaqueKEBuffer(data: password)
        let returnCode = passwordBuffer.withRawHandle { passwordHandle in
            opaque_ke_client_registration_start(passwordHandle, &outRequestHandle, &outClientRegistrationHandle)
        }

        guard returnCode == 0 else {
            throw OpaqueClientError.registrationStartFailure(code: returnCode)
        }

        guard let request = OpaqueKEBuffer(handle: outRequestHandle),
              let clientRegistration = OpaqueKEBuffer(handle: outClientRegistrationHandle),
              let requestData = request.data
        else {
            throw OpaqueClientError.missingRegistrationStartOutputs
        }

        return (request: requestData, clientRegistrationHandle: clientRegistration)
    }

    /// Completes the client registration process using the server's registration response.
    /// - Parameters:
    ///   - clientRegistrationHandle: The client registration handle from `clientRegistrationStart`.
    ///   - password: The password as data bytes.
    ///   - registrationResponse: The server's registration response data.
    /// - Returns: A tuple containing the registration upload data to send to the server and the export key.
    /// - Throws: An `OpaqueClientError` if the operation fails.
    static public func registrationFinish(clientRegistrationHandle: OpaqueKEBuffer,
                                          password: Data,
                                          registrationResponse: Data) throws -> (registrationUpload: Data, exportKey: Data) {
        var outUploadHandle: UnsafeMutableRawPointer?
        var outExportKeyHandle: UnsafeMutableRawPointer?

        // create password and response buffer handles using OpaqueKEBuffer
        let passwordBuffer = OpaqueKEBuffer(data: password)
        let responseBuffer = OpaqueKEBuffer(data: registrationResponse)

        let returnCode = clientRegistrationHandle.withRawHandle { regHandle in
            passwordBuffer.withRawHandle { passwordHandle in
                responseBuffer.withRawHandle { responseHandle in
                    opaque_ke_client_registration_finish(regHandle, passwordHandle, responseHandle,
                                                         &outUploadHandle, &outExportKeyHandle)
                }
            }
        }

        guard returnCode == 0 else {
            throw OpaqueClientError.registrationFinishFailure(code: returnCode)
        }

        guard let uploadBuffer = OpaqueKEBuffer(handle: outUploadHandle),
              let exportBuffer = OpaqueKEBuffer(handle: outExportKeyHandle),
              let uploadData = uploadBuffer.data,
              let exportData = exportBuffer.data
        else {
            throw OpaqueClientError.missingRegistrationFinishOutputs
        }

        return (registrationUpload: uploadData, exportKey: exportData)
    }
}
