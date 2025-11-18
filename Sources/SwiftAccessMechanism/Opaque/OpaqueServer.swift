//
//  Server.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-20.
//

import Foundation
import BigInt
import CryptoKit

public class OpaqueServer {
    private let oprfCurve: OprfCurve
    private let skS: OpaqueSecretKey
    private let serializedPkS: OpaquePublicKey
    private let keyDerivation: KeyDerivationProtocol
    private let hash: DigestAlgorithm
    private let context: Data

    fileprivate var testingNonce: Data?
    fileprivate var testingMaskingNonce: Data?
    fileprivate var testingKeyshareSeed: Data?

    enum OpaqueServerError: Error {
        case ClientAuthenticationError
        case notAllowedWhenNotTesting
    }

    convenience public init(oprfCurve: OprfCurve, skS: OpaqueSecretKey, context: Data) {
        self.init(oprfCurve: oprfCurve, skS: skS, keyDerivation: HKDFKeyDerivation(), hash: SHA256Algorithm(), context: context)
    }

    /// Initialize the server with an OPRF curve instance, the server secret scalar (skS),
    /// and a key derivation protocol.
    ///
    /// - Parameters:
    ///   - oprfCurve: The OPRF curve instance.
    ///   - skS: The server's secret scalar.
    ///   - keyDerivation: The key derivation protocol to use. Defaults to `HKDFKeyDerivation()`.
    init(oprfCurve: OprfCurve, skS: OpaqueSecretKey, keyDerivation: KeyDerivationProtocol, hash: DigestAlgorithm, context: Data) {
        self.oprfCurve = oprfCurve
        self.skS = skS
        self.keyDerivation = keyDerivation
        self.serializedPkS = try! OpaquePublicKey(oprfCurve.computePublicKey(curve: oprfCurve.ecCurve, skS: skS.value))
        self.hash = hash
        self.context = context
    }

    // Registration response returned to the client containing the serialized evaluated element and server public key
    public struct RegistrationResponse: Equatable {
        public let evaluatedMessage: Data
        public let serverPublicKey: OpaquePublicKey

        public init(evaluatedMessage: Data, serverPublicKey: OpaquePublicKey) {
            self.evaluatedMessage = evaluatedMessage
            self.serverPublicKey = serverPublicKey
        }

        var data: Data {
            return evaluatedMessage + serverPublicKey.data
        }
    }

    /// Represents an authentication response sent by the server.
    public struct AuthResponse: Equatable {
        public let serverNonce: Data
        public let serverPublicKeyshare: OpaquePublicKey
        public let serverMac: Data

        public init(serverNonce: Data, serverPublicKeyshare: OpaquePublicKey, serverMac: Data) {
            self.serverNonce = serverNonce
            self.serverPublicKeyshare = serverPublicKeyshare
            self.serverMac = serverMac
        }

        var data: Data {
            return serverNonce + serverPublicKeyshare.data + serverMac
        }
    }

    /// Represents a credential response sent by the server.
    public struct CredentialResponse: Equatable {
        public let evaluatedMessage: Data
        public let maskingNonce: Data
        public let maskedResponse: Data

        public init(evaluatedMessage: Data, maskingNonce: Data, maskedResponse: Data) {
            self.evaluatedMessage = evaluatedMessage
            self.maskingNonce = maskingNonce
            self.maskedResponse = maskedResponse
        }

        var data: Data {
            return evaluatedMessage + maskingNonce + maskedResponse
        }
    }

    /// CreateRegistrationResponse
    /// - Input: request, server_public_key, credential_identifier, oprf_seed
    /// - Output: RegistrationResponse containing the evaluated element and server public key
    /// - Throws: DeserializeError, DeriveKeyPairError
    func createRegistrationResponse(
        request: OpaqueClient.RegistrationRequest,
        credentialIdentifier: Data,
        oprfSeed: Data
    ) throws -> RegistrationResponse {
        // Expand the OPRF seed to derive the OPRF key
        let seed = keyDerivation.Expand(
            prk: oprfSeed,
            info: credentialIdentifier + Data("OprfKey".utf8),
            outputLength: keyDerivation.extractSize
        )
        let (oprfKey, _) = try oprfCurve.deriveKeyPair(
            seed: seed,
            info: Data("OPAQUE-DeriveKeyPair".utf8)
        )

        // Evaluate the blinded element from the request using the OPRF key
        let evaluatedMessage = try oprfCurve.blindEvaluate(skS: oprfKey, blindedElement: request.blindedMessage)

        // Create and return the RegistrationResponse
        return RegistrationResponse(
            evaluatedMessage: evaluatedMessage,
            serverPublicKey: self.serializedPkS
        )
    }

    /// CreateCredentialResponse
    /// - Parameters:
    ///   - request: The client's credential request containing the blinded element.
    ///   - serverPublicKey: The server's public key.
    ///   - record: The registration record associated with the client.
    ///   - credentialIdentifier: The identifier for the credential.
    ///   - oprfSeed: The seed used for OPRF key derivation.
    /// - Returns: A `CredentialResponse` containing the evaluated message, masking nonce, and masked response.
    /// - Throws: Errors related to key derivation, element serialization/deserialization, and OPRF evaluation.
    func createCredentialResponse(
        request: OpaqueClient.CredentialRequest,
        serverPublicKey: OpaquePublicKey,
        record: OpaqueClient.RegistrationRecord,
        credentialIdentifier: Data,
        oprfSeed: Data,
        keyDerivation: KeyDerivationProtocol
    ) throws -> CredentialResponse {
        // Expand the OPRF seed to derive the OPRF key
        let seed = keyDerivation.Expand(
            prk: oprfSeed,
            info: credentialIdentifier + Data("OprfKey".utf8),
            outputLength: keyDerivation.extractSize
        )
        let (oprfKey, _) = try oprfCurve.deriveKeyPair(
            seed: seed,
            info: Data("OPAQUE-DeriveKeyPair".utf8),
        )

        // Evaluate the blinded element using the OPRF key
        let evaluatedMessage = try oprfCurve.blindEvaluate(skS: oprfKey, blindedElement: request.blindedMessage)

        #if DEBUG
        // Allow injecting specific values during testing
        let maskingNonce = try self.testingMaskingNonce ?? randomBytes(self.keyDerivation.nonceSize)
        #else
        if self.testingMaskingNonce != nil {
            throw OpaqueServerError.notAllowedWhenNotTesting
        }
        // Generate a random masking nonce
        let maskingNonce = try randomBytes(keyDerivation.nonceSize)
        #endif

        // Derive the credential response pad
        let credentialResponsePad = keyDerivation.Expand(
            prk: record.maskingKey,
            info: maskingNonce + Data("CredentialResponsePad".utf8),
            outputLength: serverPublicKey.value.count + record.envelope.nonce.count + record.envelope.authTag.count
        )

        // Mask the response
        let maskedResponse = try H2cUtils.xor(
            credentialResponsePad,
            serverPublicKey.value + record.envelope.nonce + record.envelope.authTag
        )

        // Create and return the CredentialResponse
        return CredentialResponse(
            evaluatedMessage: evaluatedMessage,
            maskingNonce: maskingNonce,
            maskedResponse: maskedResponse
        )
    }

    /// A struct to hold the KE2 message and the associated server state.
    public struct KE2WithState {
        public let ke2: KE2
        public let serverState: OpaqueServerState
    }

    /// Represents the second message (KE2) in the OPAQUE protocol.
    public struct KE2: Equatable {
        /// A CredentialResponse structure.
        public let credentialResponse: CredentialResponse

        /// An AuthResponse structure.
        public let authResponse: AuthResponse

        public init(credentialResponse: CredentialResponse, authResponse: AuthResponse) {
            self.credentialResponse = credentialResponse
            self.authResponse = authResponse
        }

        var data: Data {
            return credentialResponse.data + authResponse.data
        }
    }

    /// A small state object to hold the expected client MAC and session key.
    public struct OpaqueServerState {
        fileprivate var expectedClientMac: Data
        fileprivate var sessionKey: Data
    }

    /// The `GenerateKE2` function continues the AKE protocol by processing the client's KE1 message
    /// and producing the server's KE2 output along with the server state.
    ///
    /// - Parameters:
    ///   - serverIdentity: The optional encoded server identity, which is set to `serverPublicKey` if not specified.
    ///   - serverPrivateKey: The server's private key.
    ///   - serverPublicKey: The server's public key.
    ///   - record: The client's `RegistrationRecord` structure.
    ///   - credentialIdentifier: An identifier that uniquely represents the credential.
    ///   - oprfSeed: The server-side seed of Nh bytes used to generate an OPRF key.
    ///   - ke1: A `KE1` message structure.
    ///   - clientIdentity: The optional encoded client identity, which is set to `clientPublicKey` if not specified.
    /// - Returns: A `KE2WithState` structure containing the server's KE2 message and state.
    /// - Throws: Errors related to key derivation, element serialization/deserialization, and OPRF evaluation.
    public func GenerateKE2(
        serverIdentity: Data?,
        serverPrivateKey: OpaqueSecretKey,
        serverPublicKey: OpaquePublicKey,
        record: OpaqueClient.RegistrationRecord,
        credentialIdentifier: Data,
        oprfSeed: Data,
        ke1: OpaqueClient.KE1,
        clientIdentity: Data?
    ) throws -> KE2WithState {
        // Set default values for optional parameters
        let resolvedServerIdentity = serverIdentity ?? serverPublicKey.data
        let resolvedClientIdentity = clientIdentity ?? record.clientPublicKey.data

        // Create the CredentialResponse
        let credentialResponse = try createCredentialResponse(
            request: ke1.credentialRequest,
            serverPublicKey: serverPublicKey,
            record: record,
            credentialIdentifier: credentialIdentifier,
            oprfSeed: oprfSeed,
            keyDerivation: HKDFKeyDerivation()
        )

        // Create the CleartextCredentials
        let cleartextCredentials = OpaqueEnvelope.CleartextCredentials(
            serverPublicKey: serverPublicKey,
            serverIdentity: resolvedServerIdentity,
            clientIdentity: resolvedClientIdentity
        )

        // Generate the AuthResponse and server state
        let (authResponse, serverState) = try AuthServerRespond(
            cleartextCredentials: cleartextCredentials,
            serverPrivateKey: serverPrivateKey,
            clientPublicKey: record.clientPublicKey,
            ke1: ke1,
            credentialResponse: credentialResponse
        )

        // Construct the KE2 structure
        let ke2 = KE2(
            credentialResponse: credentialResponse,
            authResponse: authResponse
        )

        // Return the KE2WithState structure
        return KE2WithState(ke2: ke2, serverState: serverState)
    }

    /// The `AuthServerRespond` function is used by the server to process the client's KE1 message
    /// and public credential information to create a KE2 message.
    ///
    /// - Parameters:
    ///   - cleartextCredentials: A `CleartextCredentials` structure containing the server and client identities.
    ///   - serverPrivateKey: The server's private key.
    ///   - clientPublicKey: The client's public key.
    ///   - ke1: A `KE1` message structure.
    ///   - credentialResponse: The `CredentialResponse` structure generated during the KE2 process.
    /// - Returns: A tuple containing an `AuthResponse` structure and an `OpaqueServerState` object.
    /// - Throws: Errors related to key derivation, Diffie-Hellman operations, or MAC generation.
    func AuthServerRespond(
        cleartextCredentials: OpaqueEnvelope.CleartextCredentials,
        serverPrivateKey: OpaqueSecretKey,
        clientPublicKey: OpaquePublicKey,
        ke1: OpaqueClient.KE1,
        credentialResponse: CredentialResponse
    ) throws -> (AuthResponse, OpaqueServerState) {
        #if DEBUG
        // Allow injecting specific values during testing
        let serverNonce = try self.testingNonce ?? randomBytes(self.keyDerivation.nonceSize)

        let serverKeyshareSeed = try self.testingKeyshareSeed ?? randomBytes(self.keyDerivation.seedSize)
        #else
        if self.testingNonce != nil || self.testingKeyshareSeed != nil {
            throw OpaqueServerError.notAllowedWhenNotTesting
        }
        // Generate a random nonce
        let serverNonce = try randomBytes(self.keyDerivation.nonceSize)

        // Generate a random seed for the Diffie-Hellman key pair
        let serverKeyshareSeed = try randomBytes(self.keyDerivation.seedSize)
        #endif
        let (serverPrivateKeyshare, serverPublicKeyshare) = try OpaqueUtils.deriveDiffieHellmanKeyPair(oprf: self.oprfCurve, seed: serverKeyshareSeed)

        // Perform Diffie-Hellman operations and compute AKE components
        let akeComponents = try OpaqueUtils.computeAKEComponents(
            oprfCurve: self.oprfCurve,
            keyDerivation: self.keyDerivation,
            hash: self.hash,
            context: self.context,
            dhInputs: (
                privateKey1: serverPrivateKeyshare,
                privateKey2: serverPrivateKey,
                privateKey3: serverPrivateKeyshare,
                publicKey1: ke1.authRequest.clientPublicKeyshare,
                publicKey2: ke1.authRequest.clientPublicKeyshare,
                publicKey3: clientPublicKey,
            ),
            cleartextCredentials: cleartextCredentials,
            ke1: ke1,
            credentialResponse: credentialResponse,
            serverNonce: serverNonce,
            serverPublicKeyshare: serverPublicKeyshare
        )

        // Create the server state
        let serverState = OpaqueServerState(expectedClientMac: akeComponents.clientMac, sessionKey: akeComponents.sessionKey)

        // Construct and return the AuthResponse and server state
        return (
            AuthResponse(
                serverNonce: serverNonce,
                serverPublicKeyshare: serverPublicKeyshare,
                serverMac: akeComponents.serverMac
            ),
            serverState
        )
    }

    /// The `ServerFinish` function is used to finalize the authentication process by validating the KE3 message
    /// and returning the shared session key. The server MUST NOT use the sesion key before this function has been called.
    ///
    /// - Parameters:
    ///   - ke3: A `KE3` structure containing the client's MAC.
    ///   - state: The `OpaqueServerState` object containing the expected client MAC and session key.
    /// - Returns: The shared session key if and only if the KE3 message is valid.
    /// - Throws: A `ClientAuthenticationError` if the handshake fails due to an invalid client MAC.
    public func ServerFinish(ke3: OpaqueClient.KE3, state: OpaqueServerState) throws -> Data {
        return try AuthServerFinalize(ke3: ke3, serverState: state)
    }

    /// The `AuthServerFinalize` function is used by the server to process the client's KE3 message
    /// and output the final session key.
    ///
    /// - Parameters:
    ///   - ke3: A `KE3` structure containing the client's MAC.
    ///   - serverState: The `OpaqueServerState` object containing the expected client MAC and session key.
    /// - Returns: The shared session key if and only if the KE3 message is valid.
    /// - Throws: A `ClientAuthenticationError` if the handshake fails due to an invalid client MAC.
    func AuthServerFinalize(ke3: OpaqueClient.KE3, serverState: OpaqueServerState) throws -> Data {
        // Verify the client's MAC against the expected MAC
        guard OpaqueUtils.ct_equal(ke3.clientMac, serverState.expectedClientMac) else {
            throw OpaqueServerError.ClientAuthenticationError
        }

        // Return the session key
        return serverState.sessionKey
    }


    #if DEBUG
    /// Sets a testing nonce. Only available in debug builds.
    internal func setTestingNonce(_ nonce: Data?) {
        self.testingNonce = nonce
    }

    /// Sets a testing blinding scalar. Only available in debug builds.
    internal func setTestingMaskingNonce(_ nonce: Data?) {
        self.testingMaskingNonce = nonce
    }

    /// Sets a testing blinding scalar. Only available in debug builds.
    internal func setTestingKeyshareSeed(_ seed: Data?) {
        self.testingKeyshareSeed = seed
    }
    #endif
}
