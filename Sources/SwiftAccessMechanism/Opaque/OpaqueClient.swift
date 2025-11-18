//
//  Client.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-15.
//

import Foundation
import SwiftECC
import BigInt
import CryptoKit // Add this import to use HKDF

public class OpaqueClient {
    private let oprfCurve: OprfCurve
    private let keyDerivation: KeyDerivationProtocol
    private let hash: DigestAlgorithm
    private let context: Data

    fileprivate var testingNonce: Data? = nil
    fileprivate var testingBlindingScalar: BInt? = nil
    fileprivate var testingKeyshareSeed: Data? = nil

    // Error types for the Opaque client
    public enum OpaqueClientError: Error {
        case InvalidInputError(String)
        case notAllowedWhenNotTesting
        case ServerAuthenticationError
    }

    convenience public init(oprfCurve: OprfCurve, context: Data) {
        self.init(oprfCurve: oprfCurve, keyDerivation: HKDFKeyDerivation(), hash: SHA256Algorithm(), context: context)
    }

    internal init(oprfCurve: OprfCurve, keyDerivation: KeyDerivationProtocol, hash: DigestAlgorithm, context: Data) {
        self.oprfCurve = oprfCurve
        self.keyDerivation = keyDerivation
        self.hash = hash
        self.context = context
    }

    // Registration request returned to the server containing the serialized blinded element
    public struct RegistrationRequest: Equatable {
        public let blindedMessage: Bytes
        public init(blindedMessage: Bytes) {
            self.blindedMessage = blindedMessage
        }

        var data: Data {
            return Data(self.blindedMessage)
        }
    }

    // Registration record returned to the client
    public struct RegistrationRecord: Equatable {
        public let clientPublicKey: OpaquePublicKey
        public let maskingKey: Data
        public let envelope: OpaqueEnvelope.Envelope

        public enum OpaqueRegistrationRecordError: Error {
            case RegistrationRecordRecoveryError(String)
        }


        public init(clientPublicKey: OpaquePublicKey, maskingKey: Data, envelope: OpaqueEnvelope.Envelope) {
            self.clientPublicKey = clientPublicKey
            self.maskingKey = maskingKey
            self.envelope = envelope
        }

        public init(fromData data: Data, client: OpaqueClient) throws {
            try self.init(fromData: data,
                      keyLength: client.oprfCurve.pointSerializationLength,
                      hashLength: client.hash.digestSize(),
                      nonceLength: client.keyDerivation.nonceSize,
            )
        }

        /// Initializes an Envelope from serialized data.
        /// - Parameter data: The serialized data produced by the `data` property.
        /// - Throws: An error if the data is invalid or cannot be parsed.
        public init(fromData dataIn: Data, keyLength: Int, hashLength: Int, nonceLength: Int) throws {
            // Create a copy of the data to ensure it is not modified unexpectedly
            let data = Data(dataIn)

            guard data.count >= keyLength + hashLength else {
                throw OpaqueRegistrationRecordError.RegistrationRecordRecoveryError("Invalid data, got \(data.count) bytes, expected >= \(keyLength + hashLength)")
            }
            var offset = 0
            let clientPublicKey = OpaquePublicKey(data.subdata(in: offset..<offset + keyLength).bytes)
            offset += keyLength
            let maskingKey = data.subdata(in: offset..<offset + hashLength)
            offset += hashLength
            let envelopeData = data.subdata(in: offset..<data.count)
            let envelope = try OpaqueEnvelope.Envelope(fromData: envelopeData, nonceLength: nonceLength, hashLength: hashLength)

            self.init(clientPublicKey: clientPublicKey, maskingKey: maskingKey, envelope: envelope)
        }

        var data: Data {
            return clientPublicKey.data + maskingKey + envelope.data
        }
    }

    public struct CredentialRequest: Equatable {
        public let blindedMessage: Bytes

        public init(blindedMessage: Bytes) {
            self.blindedMessage = blindedMessage
        }

        var data: Data {
            return Data(self.blindedMessage)
        }
    }

    /// Represents an authentication request sent by the client.
    public struct AuthRequest: Equatable {
        /// A fresh randomly generated nonce of length Nn.
        public let clientNonce: Data

        /// A serialized client ephemeral public key of fixed size Npk.
        public let clientPublicKeyshare: OpaquePublicKey

        public init(clientNonce: Data, clientPublicKeyshare: OpaquePublicKey) {
            self.clientNonce = clientNonce
            self.clientPublicKeyshare = clientPublicKeyshare
        }

        var data: Data {
            return clientNonce + clientPublicKeyshare.data
        }
    }

    /// Represents the first message (KE1) in the OPAQUE protocol.
    public struct KE1: Equatable {
        /// A CredentialRequest structure.
        public let credentialRequest: CredentialRequest

        /// An AuthRequest structure.
        public let authRequest: AuthRequest

        public init(credentialRequest: CredentialRequest, authRequest: AuthRequest) {
            self.credentialRequest = credentialRequest
            self.authRequest = authRequest
        }

        var data: Data {
            return self.credentialRequest.data + self.authRequest.data
        }

    }

    /// Represents the third message (KE3) in the OPAQUE protocol.
    public struct KE3: Codable, Equatable {
        /// An authentication tag computed over the handshake transcript of fixed size Nm, computed using Km2, defined below.
        public let clientMac: Data

        public init(clientMac: Data) {
            self.clientMac = clientMac
        }

        var data: Data {
            return self.clientMac
        }
    }

    /// CreateRegistrationRequest
    /// - Input: password - opaque byte string containing the client's password
    /// - Output: (request, blind)
    /// - Throws: InvalidInputError when blind() fails
    public func createRegistrationRequest(password: Data) throws -> (RegistrationRequest, BInt) {
        #if !DEBUG
        if self.testingBlindingScalar != nil {
            throw OpaqueClientError.notAllowedWhenNotTesting
        }
        #endif
        do {
            let (blind, blindedElement) = try self.oprfCurve.blind(input: password, testingScalar: self.testingBlindingScalar)
            let request = RegistrationRequest(blindedMessage: blindedElement)
            return (request, blind)
        } catch {
            // Map any failure from blind to InvalidInputError
            throw OpaqueClientError.InvalidInputError("Failed to blind input: \(error)")
        }
    }

    /// FinalizeRegistrationRequest
    /// - Input: password, blind, response, server_identity, client_identity
    /// - Output: (record, export_key)
    /// - Throws: DeserializeError when OPRF element deserialization fails
    public func finalizeRegistrationRequest(
        password: Data,
        blind: BInt,
        response: OpaqueServer.RegistrationResponse,
        serverIdentity: Data?,
        clientIdentity: Data?,
    ) throws -> (RegistrationRecord, Data) {
        #if !DEBUG
        if self.testingNonce != nil {
            throw OpaqueClientError.notAllowedWhenNotTesting
        }
        #endif
        // Finalize the OPRF flow
        let oprfOutput = try self.oprfCurve.finalize(input: password, blind: blind, evaluatedElement: response.evaluatedMessage)

        // Stretch the OPRF output
        let stretchedOprfOutput = Stretch(oprfOutput)

        // Derive the randomized password
        let randomizedPassword = keyDerivation.Extract(salt: Data("".utf8), keyMaterial: oprfOutput + stretchedOprfOutput)

        // Store the credentials and derive keys
        let (envelope, clientPublicKey, maskingKey, exportKey) = try OpaqueEnvelope.Store(
            randomizedPassword: randomizedPassword,
            serverPublicKey: response.serverPublicKey,
            serverIdentity: serverIdentity,
            clientIdentity: clientIdentity,
            oprf: self.oprfCurve,
            hash: self.hash,
            keyDerivation: self.keyDerivation,
            testingNonce: self.testingNonce
        )

        // Create the registration record
        let record = RegistrationRecord(
            clientPublicKey: clientPublicKey,
            maskingKey: maskingKey,
            envelope: envelope
        )

        return (record, exportKey)
    }

    fileprivate func Stretch(_ msg: Data) -> Data {
        //return keyDerivation.Expand(prk: msg, info: Data("Stretch".utf8), outputLength: 32)
        return msg
    }

    public struct KE1WithState: Equatable {
        public let ke1: KE1
        fileprivate let clientSecret: OpaqueSecretKey
        fileprivate let blind: BInt
        fileprivate let password: Data

        public init(ke1: KE1, clientSecret: OpaqueSecretKey, blind: BInt, password: Data) {
            self.ke1 = ke1
            self.clientSecret = clientSecret
            self.blind = blind
            self.password = password
        }
    }

    /// The `GenerateKE1` function begins the AKE protocol and produces the client's KE1 output for the server.
    ///
    /// - Parameters:
    ///   - password: An opaque byte string containing the client's password.
    /// - Returns: A `KE1WithState` structure containing:
    ///   - `ke1`: A `KE1` message structure.
    ///   - `clientSecret`: The client's ephemeral private key.
    ///   - `blind`: The OPRF blind scalar value.
    /// - Throws: An error if the KE1 generation process fails.
    public func GenerateKE1(password: Data) throws -> KE1WithState {
        // Create a credential request using the client's password
        let (credentialRequest, blind) = try CreateCredentialRequest(password: password)

        // Start the authentication process and generate KE1
        let (ke1, clientSecret) = try AuthClientStart(credentialRequest)

        return KE1WithState(ke1: ke1, clientSecret: clientSecret, blind: blind, password: password)
    }

    func CreateCredentialRequest(password: Data) throws -> (CredentialRequest, BInt) {
        // Blind the password to generate a blind scalar and blinded element
        let (blind, blindedElement) = try oprfCurve.blind(input: password, testingScalar: self.testingBlindingScalar)

        // Create the CredentialRequest structure
        let request = CredentialRequest(blindedMessage: blindedElement)

        return (request, blind)
    }

    func AuthClientStart(_ credentialRequest: CredentialRequest) throws -> (KE1, OpaqueSecretKey) {
        #if DEBUG
        // Allow injecting specific values during testing
        let clientNonce = try self.testingNonce ?? randomBytes(self.keyDerivation.nonceSize)

        let clientKeyshareSeed = try self.testingKeyshareSeed ?? randomBytes(self.keyDerivation.seedSize)
        #else
        if self.testingNonce != nil || self.testingKeyshareSeed != nil {
            throw OpaqueClientError.notAllowedWhenNotTesting
        }
        // Generate a random nonce
        let clientNonce = try randomBytes(self.keyDerivation.nonceSize)

        // Generate a random seed for the Diffie-Hellman key pair
        let clientKeyshareSeed = try randomBytes(self.keyDerivation.seedSize)
        #endif

        // Derive the Diffie-Hellman key pair
        let (clientSecret, clientPublicKeyshare) = try OpaqueUtils.deriveDiffieHellmanKeyPair(oprf: self.oprfCurve, seed: clientKeyshareSeed)

        // Create the AuthRequest structure
        let authRequest = AuthRequest(clientNonce: clientNonce, clientPublicKeyshare: clientPublicKeyshare)

        // Create the KE1 structure
        let ke1 = KE1(credentialRequest: credentialRequest, authRequest: authRequest)

        return (ke1, clientSecret)
    }

    /// The `GenerateKE3` function completes the AKE protocol for the client and produces the client's KE3 output for the server,
    /// as well as the session_key and export_key outputs from the AKE.
    ///
    /// - Parameters:
    ///   - clientIdentity: The optional encoded client identity, which is set to `clientPublicKey` if not specified.
    ///   - serverIdentity: The optional encoded server identity, which is set to `serverPublicKey` if not specified.
    ///   - ke2: A `KE2` message structure.
    /// - Returns: A tuple containing the `KE3` message structure, the session's shared secret (`sessionKey`), and an additional client key (`exportKey`).
    /// - Throws: Errors related to credential recovery or authentication finalization.
    public func GenerateKE3(ke1WithState: KE1WithState,
                     clientIdentity: Data?,
                     serverIdentity: Data?,
                     ke2: OpaqueServer.KE2,
                     clientPublicKey: OpaquePublicKey,
                     serverPublicKey: OpaquePublicKey,
) throws -> (ke3: KE3, sessionKey: Data, exportKey: Data) {
        // Set default values for optional parameters
        let resolvedServerIdentity = serverIdentity ?? serverPublicKey.data
        let resolvedClientIdentity = clientIdentity ?? clientPublicKey.data

        // Recover the client's private key, cleartext credentials, and export key
        let (clientPrivateKey, cleartextCredentials, exportKey) = try recoverCredentials(
            password: ke1WithState.password,
            blind: ke1WithState.blind,
            response: ke2.credentialResponse,
            serverIdentity: resolvedServerIdentity,
            clientIdentity: resolvedClientIdentity
        )

        // Finalize the authentication and generate KE3 and the session key
        let (ke3, sessionKey) = try AuthClientFinalize(
            ke1WithState: ke1WithState,
            cleartextCredentials: cleartextCredentials,
            clientPrivateKey: clientPrivateKey,
            ke2: ke2
        )

        return (ke3, sessionKey, exportKey)
    }


    /// The `recoverCredentials` function is used by the client to process the server's `CredentialResponse` message
    /// and produce the client's private key, server public key, and the `exportKey`.
    ///
    /// - Parameters:
    ///   - password: An opaque byte string containing the client's password.
    ///   - blind: An OPRF scalar value.
    ///   - response: A `CredentialResponse` structure.
    ///   - serverIdentity: The optional encoded server identity.
    ///   - clientIdentity: The encoded client identity.
    /// - Returns: A tuple containing:
    ///   - `clientPrivateKey`: The encoded client private key for the AKE protocol.
    ///   - `cleartextCredentials`: A `CleartextCredentials` structure.
    ///   - `exportKey`: An additional client key.
    /// - Throws: `DeserializeError` when OPRF element deserialization fails.
    func recoverCredentials(
        password: Data,
        blind: BInt,
        response: OpaqueServer.CredentialResponse,
        serverIdentity: Data?,
        clientIdentity: Data
    ) throws -> (OpaqueSecretKey, OpaqueEnvelope.CleartextCredentials, Data) {
        // Finalize the OPRF flow to compute the OPRF output
        let oprfOutput = try oprfCurve.finalize(input: password, blind: blind, evaluatedElement: response.evaluatedMessage)

        // Stretch the OPRF output
        let stretchedOprfOutput = Stretch(oprfOutput)

        // Derive the randomized password
        let randomizedPassword = keyDerivation.Extract(salt: Data(), keyMaterial: oprfOutput + stretchedOprfOutput)

        // Derive the masking key
        let maskingKey = keyDerivation.Expand(prk: randomizedPassword, info: "MaskingKey".data(using: .ascii)!, outputLength: keyDerivation.extractSize)

        let keyLength = self.oprfCurve.pointSerializationLength
        let hashLength = self.hash.digestSize()
        let nonceLength = self.keyDerivation.nonceSize

        // Derive the credential response pad
        let credentialResponsePad = keyDerivation.Expand(
            prk: maskingKey,
            info: response.maskingNonce + "CredentialResponsePad".data(using: .ascii)!,
            outputLength: keyLength + keyDerivation.nonceSize + keyDerivation.extractSize)

        // Recover the server public key and envelope
        let maskedResponse = response.maskedResponse
        let unmaskedData = try H2cUtils.xor(credentialResponsePad, maskedResponse)
        let serverPublicKey = OpaquePublicKey(unmaskedData.prefix(keyLength).bytes)
        let envelopeData = unmaskedData.suffix(unmaskedData.count - keyLength)
        let envelope = try OpaqueEnvelope.Envelope(fromData: envelopeData, nonceLength: nonceLength, hashLength: hashLength)

        // Recover the client private key, cleartext credentials, and export key
        let (clientPrivateKey, cleartextCredentials, exportKey) = try OpaqueEnvelope.recover(
            randomizedPassword: randomizedPassword,
            serverPublicKey: serverPublicKey,
            envelope: envelope,
            serverIdentity: serverIdentity,
            clientIdentity: clientIdentity,
            oprf: self.oprfCurve,
            hash: self.hash,
            keyDerivation: self.keyDerivation,
        )

        return (clientPrivateKey, cleartextCredentials, exportKey)
    }

    /// The `AuthClientFinalize` function is used by the client to create a KE3 message and output the session key
    /// using the server's KE2 message and recovered credential information.
    ///
    /// - Parameters:
    ///   - cleartextCredentials: A `CleartextCredentials` structure containing the server and client identities.
    ///   - clientPrivateKey: The client's private key.
    ///   - ke2: A `KE2` message structure.
    /// - Returns: A tuple containing the `KE3` message structure and the shared session secret (`sessionKey`).
    /// - Throws: A `ServerAuthenticationError` if the handshake fails.
    func AuthClientFinalize(
        ke1WithState: KE1WithState,
        cleartextCredentials: OpaqueEnvelope.CleartextCredentials,
        clientPrivateKey: OpaqueSecretKey,
        ke2: OpaqueServer.KE2
    ) throws -> (ke3: KE3, sessionKey: Data) {
        // Perform Diffie-Hellman operations and compute AKE components
        let akeComponents = try OpaqueUtils.computeAKEComponents(
            oprfCurve: self.oprfCurve,
            keyDerivation: keyDerivation,
            hash: hash,
            context: self.context,
            dhInputs: (
                privateKey1: ke1WithState.clientSecret,
                privateKey2: ke1WithState.clientSecret,
                privateKey3: clientPrivateKey,
                publicKey1: ke2.authResponse.serverPublicKeyshare,
                publicKey2: cleartextCredentials.serverPublicKey,
                publicKey3: ke2.authResponse.serverPublicKeyshare
            ),
            cleartextCredentials: cleartextCredentials,
            ke1: ke1WithState.ke1,
            credentialResponse: ke2.credentialResponse,
            serverNonce: ke2.authResponse.serverNonce,
            serverPublicKeyshare: ke2.authResponse.serverPublicKeyshare
        )

        // Verify the server's MAC
        guard OpaqueUtils.ct_equal(ke2.authResponse.serverMac, akeComponents.serverMac) else {
            throw OpaqueClientError.ServerAuthenticationError
        }

        // Create the KE3 structure
        let ke3 = KE3(clientMac: akeComponents.clientMac)

        return (ke3, akeComponents.sessionKey)
    }



    #if DEBUG
    /// Sets a testing nonce. Only available in debug builds.
    internal func setTestingNonce(_ nonce: Data?) {
        self.testingNonce = nonce
    }

    /// Sets a testing blinding scalar. Only available in debug builds.
    internal func setTestingBlindingScalar(_ scalar: BInt) {
        self.testingBlindingScalar = scalar
    }

    /// Sets a testing blinding scalar. Only available in debug builds.
    internal func setTestingKeyshareSeed(_ seed: Data?) {
        self.testingKeyshareSeed = seed
    }
    #endif
}
