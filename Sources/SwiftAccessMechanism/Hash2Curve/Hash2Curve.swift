//
//  Hash2Curve.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-08.
//

import Foundation
import BigInt
import SwiftECC

public enum Hash2CurveError: Error {
    case invalidConfiguration
    case invalidInput
    case invalidOperation
}

public class Hash2Curve {

    fileprivate let hash2Field: HashToFieldProtocol
    fileprivate let map2Curve: MapToCurveProtocol
    fileprivate let curve: Domain
    fileprivate let ecCurve: ECCurveProtocol
    internal let messageExpansion: MessageExpansionProtocol  // Used in OprfCurve

    convenience public init(profile: Hash2CurveProfile, domainSeparatorTag: Data, ecCurve: ECCurveProtocol) throws {
        let messageExpansion = try XmdMessageExpansion(digestAlgo: profile.digest, securityLevelBits: profile.k)
        let hash2Field = GenericHashToField(dst: domainSeparatorTag, messageExpansion: messageExpansion, L: profile.L, m: 1, order: profile.curve.p)
        let map2Curve = SVDWostijneMapToCurve(curve: profile.curve, ecCurve: ecCurve, Z_constant: profile.Z)

        self.init(curve: profile.curve, ecCurve: ecCurve, hash2Field: hash2Field, map2Curve: map2Curve, messageExpansion: messageExpansion)
    }

    init(curve: Domain, ecCurve: ECCurveProtocol, hash2Field: HashToFieldProtocol, map2Curve: MapToCurveProtocol, messageExpansion: MessageExpansionProtocol) {
        self.curve = curve
        self.ecCurve = ecCurve
        self.hash2Field = hash2Field
        self.map2Curve = map2Curve
        self.messageExpansion = messageExpansion
    }

    //    hash_to_curve(msg)
    //
    //    Input: msg, an arbitrary-length byte string.
    //    Output: P, a point in G.
    //
    //    Steps:
    //    1. u = hash_to_field(msg, 2)
    //    2. Q0 = map_to_curve(u[0])
    //    3. Q1 = map_to_curve(u[1])
    //    4. R = Q0 + Q1              # Point addition
    //    5. P = clear_cofactor(R)
    //    6. return P
    //
    func hash(_ message: Data) throws -> Data {
        let u: [[BInt]] = try hash2Field.process(message, count: 2)
        let q0 = try map2Curve.process(u[0][0])
        let q1 = try map2Curve.process(u[1][0])
        let r = try curve.addPoints(q0, q1)
        let p = try curve.multiplyPoint(r, BInt(curve.cofactor))
        return Data(try curve.encodePoint(p, true))
        // XXX RETURNERA EN Point ISTÄLLET FÖR DATA, DEN DESERIALISERAS DIREKT AV ANROPAREN (200 ms)
    }

    // Invoke hash2Field directly. Used in tests to test RFC test vectors.
    internal func hash2Field(_ message: Data) throws -> [[BInt]] {
        return try hash2Field.process(message, count: 2)
    }

}





