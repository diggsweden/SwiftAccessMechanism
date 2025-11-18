import Foundation
import BigInt
import CryptoKit

/// Represents an envelope used in the OPAQUE protocol.
public struct OpaqueEnvelope {

    struct CleartextCredentials: Equatable {
        public let serverPublicKey: OpaquePublicKey
        public let serverIdentity: Data
        public let clientIdentity: Data

        init(serverPublicKey: OpaquePublicKey, serverIdentity: Data, clientIdentity: Data) {
            self.serverPublicKey = serverPublicKey
            self.serverIdentity = serverIdentity
            self.clientIdentity = clientIdentity
        }

        var data: Data {
            var result = Data()

            result.append(contentsOf: serverPublicKey.value)
            result.append(contentsOf: try! H2cUtils.i2osp(serverIdentity.count, len: 2))
            result.append(serverIdentity)
            result.append(contentsOf: try! H2cUtils.i2osp(clientIdentity.count, len: 2))
            result.append(clientIdentity)

            return result
        }
    }

    public enum OpaqueEnvelopeError: Error {
        case InvalidAuthTag
        case EnvelopeRecoveryError(String)
    }

    /// OPAQUE makes use of a structure called Envelope to manage client credentials.
    /// The client creates its Envelope on registration and sends it to the server for storage.
    /// On every login, the server sends this Envelope to the client so it can recover its key material for use in the AKE.
    public struct Envelope: Equatable {
        /// A randomly sampled nonce of length Nn used to protect this Envelope.
        let nonce: Data
        /// An authentication tag protecting the contents of the Envelope, covering `envelope_nonce` and `CleartextCredentials`.
        let authTag: Data

        init(nonce: Data, authTag: Data) {
            self.nonce = nonce
            self.authTag = authTag
        }

        /// Initializes an Envelope from serialized data.
        /// - Parameter data: The serialized data produced by the `data` property.
        /// - Throws: An error if the data is invalid or cannot be parsed.
        public init(fromData dataIn: Data, nonceLength: Int, hashLength: Int) throws {
            // Create a copy of the data to ensure it is not modified unexpectedly
            let data = Data(dataIn)

            guard data.count == nonceLength + hashLength else {
                throw OpaqueEnvelopeError.EnvelopeRecoveryError("Invalid data, got \(data.count) bytes, expected \(nonceLength + hashLength)")
            }
            var offset = 0
            let nonce = data.subdata(in: offset..<offset + nonceLength)
            offset += nonceLength
            let authTag = data.subdata(in: offset..<offset + hashLength)

            self.init(nonce: nonce, authTag: authTag)
        }

        var data: Data {
            return nonce + authTag
        }
    }

    /// Clients create an Envelope at registration with the function `store` defined below.
    /// Note that `deriveDiffieHellmanKeyPair` in this function can fail with negligible probability.
    /// If this occurs, servers should re-run the function, sampling a new `envelopeNonce`, to completion.
    ///
    /// - Parameters:
    ///   - randomizedPassword: A randomized password.
    ///   - serverPublicKey: The encoded server public key for the AKE protocol.
    ///   - serverIdentity: The optional encoded server identity.
    ///   - clientIdentity: The optional encoded client identity.
    /// - Returns: A tuple containing:
    ///   - `envelope`: The client's `Envelope` structure.
    ///   - `clientPublicKey`: The client's AKE public key.
    ///   - `maskingKey`: An encryption key used by the server with the sole purpose of defending against client enumeration attacks.
    ///   - `exportKey`: An additional client key.
    /// - Throws: An error if key derivation or Diffie-Hellman key pair generation fails.
    internal static func Store(
        randomizedPassword: Data,
        serverPublicKey: OpaquePublicKey,
        serverIdentity: Data?,
        clientIdentity: Data?,
        oprf: OprfCurve,
        hash: DigestAlgorithm,
        keyDerivation: KeyDerivationProtocol,
        testingNonce: Data?,
    ) throws -> (Envelope, OpaquePublicKey, Data, Data) {
        #if DEBUG
        // Allow injecting a specific nonce during testing
        let envelopeNonce = try testingNonce ?? randomBytes(keyDerivation.nonceSize)
        #else
        // Generate a random nonce for the envelope
        let envelopeNonce = try randomBytes(keyDerivation.nonceSize)
        #endif

        // Derive the masking key, auth key, and export key
        let maskingKey = keyDerivation.Expand(prk: randomizedPassword, info: Data("MaskingKey".utf8), outputLength: keyDerivation.extractSize)
        let authKey = keyDerivation.Expand(prk: randomizedPassword, info: envelopeNonce + Data("AuthKey".utf8), outputLength: keyDerivation.extractSize)
        let exportKey = keyDerivation.Expand(prk: randomizedPassword, info: envelopeNonce + Data("ExportKey".utf8), outputLength: keyDerivation.extractSize)

        // Derive the client's Diffie-Hellman key pair
        let seed = keyDerivation.Expand(prk: randomizedPassword, info: envelopeNonce + Data("PrivateKey".utf8), outputLength: keyDerivation.seedSize)
        let (_, clientPublicKey) = try! OpaqueUtils.deriveDiffieHellmanKeyPair(oprf: oprf, seed: seed)

        // Set default values for optional parameter
        let resolvedServerIdentity = serverIdentity ?? Data(serverPublicKey.value)
        let resolvedClientIdentity = clientIdentity ?? clientPublicKey.data

        // Create the cleartext credentials
        let cleartextCredentials = CleartextCredentials(
            serverPublicKey: serverPublicKey,
            serverIdentity: resolvedServerIdentity,
            clientIdentity: resolvedClientIdentity
        )

        // Generate the authentication tag
        var authTagInput = Data()
        authTagInput.append(contentsOf: envelopeNonce)
        authTagInput.append(contentsOf: cleartextCredentials.data)
        let authTag = hash.hmac(key: authKey, data: authTagInput)

        // Create the envelope
        let envelope = Envelope(
            nonce: envelopeNonce,
            authTag: Data(authTag)
        )

        return (envelope, clientPublicKey, maskingKey, exportKey)
    }

    /// Clients recover their Envelope during login with the `recover` function defined below.
    ///
    /// - Parameters:
    ///   - randomizedPassword: A randomized password.
    ///   - serverPublicKey: The encoded server public key for the AKE protocol.
    ///   - envelope: The client's `Envelope` structure.
    ///   - serverIdentity: The optional encoded server identity.
    ///   - clientIdentity: The optional encoded client identity.
    /// - Returns: A tuple containing:
    ///   - `clientPrivateKey`: The encoded client private key for the AKE protocol.
    ///   - `cleartextCredentials`: A `CleartextCredentials` structure.
    ///   - `exportKey`: An additional client key.
    /// - Throws: `EnvelopeRecoveryError` if the Envelope fails to be recovered.
    internal static func recover(
        randomizedPassword: Data,
        serverPublicKey: OpaquePublicKey,
        envelope: Envelope,
        serverIdentity: Data?,
        clientIdentity: Data?,
        oprf: OprfCurve,
        hash: DigestAlgorithm,
        keyDerivation: KeyDerivationProtocol
    ) throws -> (OpaqueSecretKey, CleartextCredentials, Data) {
        // Derive the auth key, export key, and seed from the randomized password and envelope nonce
        let authKey = keyDerivation.Expand(
            prk: randomizedPassword,
            info: envelope.nonce + Data("AuthKey".utf8),
            outputLength: keyDerivation.extractSize
        )
        let exportKey = keyDerivation.Expand(
            prk: randomizedPassword,
            info: envelope.nonce + Data("ExportKey".utf8),
            outputLength: keyDerivation.extractSize
        )
        let seed = keyDerivation.Expand(
            prk: randomizedPassword,
            info: envelope.nonce + Data("PrivateKey".utf8),
            outputLength: keyDerivation.seedSize
        )

        // Derive the client's Diffie-Hellman key pair
        let (clientPrivateKey, _) = try OpaqueUtils.deriveDiffieHellmanKeyPair(oprf: oprf, seed: seed)

        // Create the cleartext credentials
        let cleartextCredentials = CleartextCredentials(
            serverPublicKey: serverPublicKey,
            serverIdentity: serverIdentity ?? Data(),
            clientIdentity: clientIdentity ?? Data()
        )

        // Generate the expected authentication tag
        var authTagInput = Data()
        authTagInput.append(contentsOf: envelope.nonce)
        authTagInput.append(contentsOf: cleartextCredentials.data)
        let expectedTag = hash.hmac(key: authKey, data: authTagInput)

        // Verify the authentication tag
        guard envelope.authTag == expectedTag else {
            throw OpaqueEnvelopeError.EnvelopeRecoveryError("authentication tag mismatch")
        }

        return (clientPrivateKey, cleartextCredentials, exportKey)
    }
}
