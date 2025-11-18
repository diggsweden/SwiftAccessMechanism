//
//  OpaqueUtils.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-21.
//

import Security
import Foundation
import BigInt

internal func randomBytes(_ len: Int) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: len)
    let status = SecRandomCopyBytes(kSecRandomDefault, len, &bytes)

    guard status == errSecSuccess else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
    }

    return Data(bytes)
}

/// A distinct type for Diffie-Hellman public keys on the chosen OPRF curve
public struct OpaqueSecretKey: Equatable {
    let value: BInt

    public init(_ value: BInt) {
        self.value = value
    }

    public func toBytes() -> Bytes {
        // REMOVE
        return self.value.asSignedBytes()
    }

    /// Convert to Data. Done differently (not a var data) to help avoid programmer mistakes.
    /// - Returns: <#description#>
    public func toData() -> Data {
        return Data(self.toBytes())
    }
}

/// A distinct type for Diffie-Hellman public keys on the chosen OPRF curve
public struct OpaquePublicKey: Equatable {
    let value: Data

    public init(_ value: Data) {
        self.value = value
    }

    var data: Data {
        return self.value
    }
}

internal struct OpaqueUtils {

    static func deriveDiffieHellmanKeyPair(oprf: OprfCurve, seed: Data) throws -> (OpaqueSecretKey, OpaquePublicKey) {
        let info = Data("OPAQUE-DeriveDiffieHellmanKeyPair".utf8)
        let (skS, pkS) = try oprf.deriveKeyPair(seed: seed, info: info)
        return (OpaqueSecretKey(skS), OpaquePublicKey(pkS))
    }

    /// The `constructPreamble` function computes the preamble required for the OPAQUE-3DH key schedule.
    ///
    /// - Parameters:
    ///   - context: Optional shared context information.
    ///   - clientIdentity: The optional encoded client identity, which is set to `clientPublicKey` if not specified.
    ///   - ke1: A `KE1` message structure.
    ///   - serverIdentity: The optional encoded server identity, which is set to `serverPublicKey` if not specified.
    ///   - credentialResponse: The `CredentialResponse` field from the KE2 structure.
    ///   - serverNonce: The `serverNonce` field from the `AuthResponse` structure.
    ///   - serverPublicKeyshare: The `serverPublicKeyshare` field from the `AuthResponse` structure.
    /// - Returns: The preamble, which is the protocol transcript with identities and messages.
    /// - Throws: An error if encoding fails.
    static func constructPreamble(
        context: Data,
        clientIdentity: Data,
        ke1: OpaqueClient.KE1,
        serverIdentity: Data,
        credentialResponse: OpaqueServer.CredentialResponse,
        serverNonce: Data,
        serverPublicKeyshare: OpaquePublicKey
    ) throws -> Data {
        var preamble = Data("OPAQUEv1-".utf8)

        // Append context length and context
        preamble.append(try H2cUtils.i2osp(context.count, len: 2))
        preamble.append(context)

        // Append client identity length and client identity
        preamble.append(try H2cUtils.i2osp(clientIdentity.count, len: 2))
        preamble.append(clientIdentity)

        // Append KE1 message
        preamble.append(ke1.data)

        // Append server identity length and server identity
        preamble.append(try H2cUtils.i2osp(serverIdentity.count, len: 2))
        preamble.append(serverIdentity)

        // Append credential response
        preamble.append(credentialResponse.data)

        // Append server nonce
        preamble.append(serverNonce)

        // Append server public keyshare
        preamble.append(serverPublicKeyshare.data)

        return preamble
    }

    /// The `diffieHellman` function performs a Diffie-Hellman key exchange using a private key as `BInt`
    /// and a public key as `Bytes`. It converts the inputs to CryptoKit-compatible types and derives the shared secret.
    ///
    /// - Parameters:
    ///   - privateKey: The private key of the server as a `BInt`.
    ///   - publicKey: The public key of the client as `Bytes`.
    /// - Returns: The shared secret derived from the Diffie-Hellman key exchange.
    /// - Throws: An error if the key exchange fails.
    static func diffieHellman(oprfCurve: OprfCurve, privateKey: OpaqueSecretKey, publicKey: OpaquePublicKey) throws -> Data {

        func computeDH<C: ECCurveProtocol>(curve: C, privateKey: OpaqueSecretKey, publicKey: OpaquePublicKey) throws -> Data {
            let publicPoint = try curve.decodePoint(publicKey.value)
            let res = try curve.multiplyPoint(publicPoint, privateKey.value)
            return Data(try curve.encodePoint(res, compress: true))
        }

        return try computeDH(curve: oprfCurve.ecCurve, privateKey: privateKey, publicKey: publicKey)
    }

    /// The `deriveKeys` function computes the shared secret and MAC authentication keys for the OPAQUE-3DH key exchange protocol.
    ///
    /// - Parameters:
    ///   - ikm: The input key material derived from the Diffie-Hellman key exchange.
    ///   - preamble: The protocol transcript containing identities and messages.
    /// - Returns: A tuple containing `Km2` (server MAC key), `Km3` (client MAC key), and `sessionKey` (shared session secret).
    /// - Throws: An error if key derivation fails.
    static func deriveKeys(keyDerivation: KeyDerivationProtocol, hash: DigestAlgorithm,
                    ikm: Data, preamble: Data) throws -> (Km2: Data, Km3: Data, sessionKey: Data) {
        // Extract the pseudorandom key (PRK) from the input key material
        let key = keyDerivation.Extract(salt: Data(), keyMaterial: ikm)

        let preambleHash = hash.hash(preamble)

        // Derive the handshake secret using the preamble
        let handshakeSecret = try self.expandLabel(keyDerivation: keyDerivation, key: key, label: "HandshakeSecret", context: preambleHash)

        // Derive the session key using the preamble
        let sessionKey = try self.expandLabel(keyDerivation: keyDerivation, key: key, label:  "SessionKey", context: preambleHash)

        let Km2 = try self.expandLabel(keyDerivation: keyDerivation, key: handshakeSecret, label: "ServerMAC")
        let Km3 = try self.expandLabel(keyDerivation: keyDerivation, key: handshakeSecret, label: "ClientMAC")

        return (Km2, Km3, sessionKey)
    }

    static fileprivate func expandLabel(keyDerivation: KeyDerivationProtocol, key: Data, label: String, context: Data = Data()) throws -> Data {
        return keyDerivation.Expand(
            prk: key,
            info: try getCustomLabel(label, context: context, length: keyDerivation.extractSize),
            outputLength: keyDerivation.extractSize
        )
    }

    /// Generates a custom label for OPAQUE key derivation.
    /// - Parameters:
    ///   - label: A byte array representing the label to include in the custom label.
    ///   - context: A byte array representing the context.
    ///   - length: The desired length of the output.
    /// - Returns: A byte array representing the custom label.
    /// - Throws: An error if the input is invalid.
    static fileprivate func getCustomLabel(_ label: String, context: Data, length: Int) throws -> Data {
        let opaqueLabel = Data("OPAQUE-".utf8) + Data(label.utf8)

        var result = Data()
        result.append(try H2cUtils.i2osp(length, len: 2))
        result.append(try H2cUtils.i2osp(opaqueLabel.count, len: 1))
        result.append(opaqueLabel)
        result.append(try H2cUtils.i2osp(context.count, len: 1))
        result.append(context)
        return result
    }

    /// Performs a constant-time comparison of two data inputs.
    ///
    /// - Parameters:
    ///   - a: The first data input.
    ///   - b: The second data input.
    /// - Returns: `true` if the inputs are equal, `false` otherwise.
    static func ct_equal(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }

        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }

        return result == 0
    }

    /// Computes the AKE (Authenticated Key Exchange) components, including the input key material (IKM),
    /// the preamble, and the expected server MAC.
    ///
    /// - Parameters:
    ///   - oprfCurve: The OPRF curve instance used for cryptographic operations.
    ///   - keyDerivation: The key derivation protocol to derive keys from the IKM and preamble.
    ///   - hash: The hash algorithm used for HMAC and hashing operations.
    ///   - context: The shared context data used in the preamble construction.
    ///   - dhInputs: A tuple containing the Diffie-Hellman inputs.
    ///   - cleartextCredentials: Struct with client/server public keys
    ///   - ke1: The KE1 message from the client.
    ///   - credentialResponse: The server's credential response.
    ///   - serverNonce: The server's nonce used in the AKE process.
    ///   - serverPublicKeyshare: The server's public key share.
    ///
    /// - Returns: A tuple containing:
    ///   - `ikm`: The input key material derived from the Diffie-Hellman operations.
    ///   - `preamble`: The preamble constructed from the context, identities, KE1, and other inputs.
    ///   - `expectedServerMac`: The expected server MAC derived from the IKM and preamble.
    ///
    /// - Throws: Errors related to key derivation, Diffie-Hellman operations, or MAC generation.
    static func computeAKEComponents(
        oprfCurve: OprfCurve,
        keyDerivation: KeyDerivationProtocol,
        hash: DigestAlgorithm,
        context: Data,
        dhInputs: (privateKey1: OpaqueSecretKey, privateKey2: OpaqueSecretKey, privateKey3: OpaqueSecretKey, publicKey1: OpaquePublicKey, publicKey2: OpaquePublicKey, publicKey3: OpaquePublicKey),
        cleartextCredentials: OpaqueEnvelope.CleartextCredentials,
        ke1: OpaqueClient.KE1,
        credentialResponse: OpaqueServer.CredentialResponse,
        serverNonce: Data,
        serverPublicKeyshare: OpaquePublicKey
    ) throws -> (ikm: Data, preamble: Data, serverMac: Data, clientMac: Data, sessionKey: Data) {
        // Perform Diffie-Hellman operations
        let dh1 = try OpaqueUtils.diffieHellman(oprfCurve: oprfCurve, privateKey: dhInputs.privateKey1, publicKey: dhInputs.publicKey1)
        let dh2 = try OpaqueUtils.diffieHellman(oprfCurve: oprfCurve, privateKey: dhInputs.privateKey2, publicKey: dhInputs.publicKey2)
        let dh3 = try OpaqueUtils.diffieHellman(oprfCurve: oprfCurve, privateKey: dhInputs.privateKey3, publicKey: dhInputs.publicKey3)

        // Concatenate the Diffie-Hellman outputs
        let ikm = dh1 + dh2 + dh3

        // Construct the preamble
        let preamble = try OpaqueUtils.constructPreamble(
            context: context,
            clientIdentity: cleartextCredentials.clientIdentity,
            ke1: ke1,
            serverIdentity: cleartextCredentials.serverIdentity,
            credentialResponse: credentialResponse,
            serverNonce: serverNonce,
            serverPublicKeyshare: serverPublicKeyshare
        )

        // Derive keys from the input key material (IKM) and preamble
        let (Km2, Km3, sessionKey) = try OpaqueUtils.deriveKeys(
            keyDerivation: keyDerivation, hash: hash,
            ikm: ikm, preamble: preamble
        )

        // Compute the expected server MAC
        let serverMac = hash.hmac(key: Km2, data: hash.hash(preamble))
        let clientMac = hash.hmac(key: Km3, data: hash.hash(preamble + serverMac))

        return (ikm: ikm,
                preamble: preamble,
                serverMac: serverMac,
                clientMac: clientMac,
                sessionKey: sessionKey
        )
    }

    static func formatDuration(_ duration: Duration) -> String {
        return duration.formatted(
            .units(allowed: [.milliseconds],
                   width: .abbreviated))
    }

    static func computePublicKey<C: ECCurveProtocol>(curve: C, skS: BInt) throws -> Data {
        let pkS = try curve.multiplyPoint(curve.generator, skS)
        return try curve.encodePoint(pkS, compress: true)
    }
}
