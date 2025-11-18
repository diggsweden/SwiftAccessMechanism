//
//  OprfCurve.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-09.
//

import Foundation
import BigInt
import CryptoKit
import OSLog

public class OprfCurve {

    enum OprfCurveError: Error {
        case domainSeparatorTagError
        case invalidInputError
        case deriveKeyPairError
        case notAllowedWhenNotTesting
    }

    internal let profile: Hash2CurveProfile  // accessed in tests
    internal let dstContext: OprfDSTContext  // accessed in tests
    internal let ecCurve: ECCurveProtocol
    fileprivate let h2c: Hash2Curve
    public let pointSerializationLength: Int

    fileprivate func formatDuration(_ duration: Duration) -> String {
        return duration.formatted(
            .units(allowed: [.milliseconds],
                   width: .abbreviated))
    }

    convenience public init(profile: Hash2CurveProfile, ecCurve: ECCurveProtocol) throws {
        let dstContext: OprfDSTContext
        switch profile {
        case .P256_XMD_SHA_256_SSWU_RO:
            dstContext = try OprfDSTContext(identifier: OprfDSTContext.IDENTIFIER_P256_SHA256)
        case .P384_XMD_SHA_384_SSWU_RO:
            dstContext = try OprfDSTContext(identifier: OprfDSTContext.IDENTIFIER_P384_SHA384)
        case .P521_XMD_SHA_512_SSWU_RO:
            dstContext = try OprfDSTContext(identifier: OprfDSTContext.IDENTIFIER_P521_SHA512)
        }

        try self.init(profile: profile, dstContext: dstContext, ecCurve: ecCurve)
    }

    internal init(profile: Hash2CurveProfile, dstContext: OprfDSTContext, ecCurve: ECCurveProtocol) throws {
        self.profile = profile
        self.dstContext = dstContext

        // Get the Domain Separator Tag to use with Hash2Curve
        guard let dst = dstContext.getHash2CurveDST() else {
            throw OprfCurveError.domainSeparatorTagError
        }

        self.h2c = try Hash2Curve(profile: profile, domainSeparatorTag: dst, ecCurve: ecCurve)
        self.ecCurve = ecCurve

        // Make the size of a serialized point (e.g. a public key) on this curve known
        self.pointSerializationLength = try profile.curve.encodePoint(profile.curve.g, true).count
    }

    internal func hash2Curve(_ message: Data) throws -> Data {
        return try h2c.hash(message)
    }

    internal func hash2Scalar(_ message: Data, domain: String = "") throws -> BInt {
        let dst = domain.isEmpty ? dstContext.getHash2ScalarDefaultDST() : dstContext.getDomainSeparationTag(domain)
        guard let dst else {
            throw OprfCurveError.domainSeparatorTagError
        }
        return try self.hash2Scalar(message, dst: dst)
    }

    internal func hash2Scalar(_ message: Data, dst: Data) throws -> BInt {
        let order = profile.curve.order
        let msgExpand = try h2c.messageExpansion.expandMessage(message, dst: dst, byteLen: profile.L)
        let scalar = BInt(magnitude: msgExpand.bytes) % order
        return scalar
    }

    /// Blinds a Point using a random scalar (BInt) on the curve for this OprfCurve.
    ///
    /// "The OPRF protocol begins with the client blinding its input, as described by the Blind function below."
    /// "Clients store blind locally and send blindedElement to the server for evaluation."
    ///
    /// - Parameter input: The input data to hash to a group element and blind.
    /// - Returns: A tuple (blindingScalar, blindedElement)
    /// - Throws: An error if the input hashes to the identity element.
    public func blind(input: Data, testingScalar: BInt? = nil) throws -> (BInt, Data) {
        let curve = self.profile.curve
        let clock = ContinuousClock()

        var blindingScalar: BInt = BInt.ZERO

#if DEBUG
            // Allow injecting a specific blinding scalar during testing
            blindingScalar = testingScalar ?? curve.order.randomLessThan()
#else
            if testingScalar != nil {
                throw OprfCurveError.notAllowedWhenNotTesting
            }
            // TODO: Should this be cryptographically random?
            blindingScalar = curve.order.randomLessThan()
#endif

        func computeEncoded<C: ECCurveProtocol>(curve: C, input: Data) throws -> Data {
            // Hash input to a group element
            var inputElementData = try self.hash2Curve(input)
            let inputElement = try curve.decodePoint(inputElementData)

            let blindedElement = try curve.multiplyPoint(inputElement, blindingScalar)
            return try curve.encodePoint(blindedElement, compress: true)
        }

        let encoded = try computeEncoded(curve: self.ecCurve, input: input)

        return (blindingScalar, encoded)
    }
//    /// Deserialize a serialized curve element (Bytes) into a Point.
//    /// - Parameter bytes: The encoded point as Bytes (compressed or uncompressed).
//    /// - Returns: The decoded Point on the curve.
//    public func deserializeElement(_ bytes: Bytes) throws -> Point {
//        let curve = self.profile.curve
//        let element = try curve.decodePoint(bytes)
//        if element.infinity {
//            throw OprfCurveError.invalidInputError
//        }
//        return element
//    }
//
//    /// Deserialize a serialized curve element (Data) into a Point.
//    /// - Parameter data: The encoded point as Data (compressed or uncompressed bytes).
//    /// - Returns: The decoded Point on the curve.
//    public func deserializeElement(_ data: Data) throws -> Point {
//        return try deserializeElement([UInt8](data))
//    }
//
//    /// Serialize a curve element (Point) using compressed point encoding.
//    /// - Parameter element: The point to serialize.
//    /// - Returns: The compressed encoded point as Bytes.
//    public func serializeElement(_ element: Point) throws -> Bytes {
//        return try self.profile.curve.encodePoint(element, true)
//    }

    /// Evaluates a blinded element with the given secret scalar (skS). This is a server operation and only used in this (client) implementation for tests.
    ///
    /// "Clients store blind locally and send blindedElement to the server for evaluation.
    /// Upon receipt, servers process blindedElement using the BlindEvaluate function described below."
    ///
    /// "Servers send the output evaluatedElement to clients for processing."
    ///
    /// - Parameters:
    ///   - skS: The secret scalar (BInt)
    ///   - blindedElement: The blinded group element (compressed bytes)
    /// - Returns: The evaluated element (compressed bytes)
    /// - Throws: If decoding or multiplication fails
    internal func blindEvaluate(skS: BInt, blindedElement: Data) throws -> Data {
        return try self.multiplyEncoded(curve: ecCurve, data: blindedElement, with: skS)
    }

    /// Finalizes the OPRF protocol by unblinding and hashing the result.
    ///
    /// "Upon receipt of evaluatedElement, clients process it to complete the OPRF evaluation with the Finalize function described below."
    ///
    /// - Parameters:
    ///   - input: The original input (Data)
    ///   - blind: The blinding scalar (BInt)
    ///   - evaluatedElement: The evaluated element (compressed bytes)
    /// - Returns: The OPRF output as Data
    public func finalize(input: Data, blind: BInt, evaluatedElement: Data) throws -> Data {
        let curve = self.profile.curve
        // 1. Scalar inverse
        let blindInv = blind.modInverse(curve.order)
        // 2. Unblinding: N = blindInv * evaluatedElement
        let unblindedElement = try self.multiplyEncoded(curve: ecCurve, data: evaluatedElement, with: blindInv)
        // 3. Hash input construction
        let inputLen = try H2cUtils.i2osp(input.count, len: 2)
        let unblindedLen = try H2cUtils.i2osp(unblindedElement.count, len: 2)
        let finalizeLabel = "Finalize".data(using: .utf8)!
        var hashInput = Data()
        hashInput.append(contentsOf: inputLen)
        hashInput.append(contentsOf: input)
        hashInput.append(contentsOf: unblindedLen)
        hashInput.append(contentsOf: unblindedElement)
        hashInput.append(contentsOf: finalizeLabel)
        // 4. Hashing using the profile's digest
        let hash = profile.digest.hash(hashInput)
        return hash
    }


    /// Derive keys deterministically using method described in RFC9497,  3.2.1. Deterministic Key Generation.
    /// - Parameters:
    ///   - seed: Secret seed for this keypair
    ///   - info: Public information
    /// - Returns: Key pair as one scalar (secret) and one point on the curve (public)
    internal func deriveKeyPair(seed: Data, info: Data) throws -> (BInt, Data) {
        let deriveInput = try seed + H2cUtils.i2osp(info.count, len: 2) + info
        var counter: UInt8 = 0
        var skS: BInt? = nil

        while skS == nil || skS!.isZero {
            if counter > 255 {
                throw OprfCurveError.deriveKeyPairError
            }

            let hashInput = try deriveInput + H2cUtils.i2osp(Int(counter), len: 1)
            skS = try self.hash2Scalar(hashInput, dst: Data("DeriveKeyPair".utf8) + self.dstContext.contextString)
            counter += 1
        }

        guard let skS else {
            throw OprfCurveError.deriveKeyPairError
        }

        let pkS = try computePublicKey(curve: self.ecCurve, skS: skS)

        return (skS, pkS)
    }

    internal func computePublicKey<C: ECCurveProtocol>(curve: C, skS: BInt) throws -> Data {
        let pkS = try curve.multiplyPoint(curve.generator, skS)
        return try curve.encodePoint(pkS, compress: true)
    }

    internal func multiplyEncoded<C: ECCurveProtocol>(curve: C, data: Data, with scalar: BInt) throws -> Data {
        let point = try curve.decodePoint(data)
        let evaluatedElement = try curve.multiplyPoint(point, scalar)
        return Data(try curve.encodePoint(evaluatedElement, compress: true))
    }
}

