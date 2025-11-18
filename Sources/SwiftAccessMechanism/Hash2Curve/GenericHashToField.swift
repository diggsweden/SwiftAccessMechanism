//
//  GenericHashToField.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-08.
//

import Foundation
import BigInt
import SwiftECC

internal class GenericHashToField: HashToFieldProtocol {

    let messageExpansion: MessageExpansionProtocol
    let dst: Data
    let L: Int
    let m: Int
    let order: BInt

    /// Initializes a `GenericHashToField` instance with the given parameters.
    /// - Parameters:
    ///   - dst: Domain Separation Tag, used to separate cryptographic usages.
    ///   - curve: The elliptic curve domain parameters.
    ///   - digest: The digest algorithm used for hashing.
    ///   - L: The output length in bytes.
    ///   - k: The security level requested in bits.
    convenience init(dst: Data, curve: Domain, digest: DigestAlgorithm, L: Int, securityLevelBits k: Int) throws {
        let messageExpansion = try XmdMessageExpansion(digestAlgo: digest, securityLevelBits: k)
        let m = curve.cofactor
        let order = curve.order
        self.init(dst: dst, messageExpansion: messageExpansion, L: L, m: m, order: order)
    }

    /// Initializes a `GenericHashToField` instance with the given parameters.
    /// - Parameters:
    ///   - dst: Domain Separation Tag, used to separate cryptographic usages.
    ///   - messageExpansion: The message expansion mechanism to use.
    ///   - L: The output length in bytes.
    ///   - m: The cofactor of the elliptic curve.
    ///   - order: The order of the elliptic curve.
    init(dst: Data, messageExpansion: MessageExpansionProtocol, L: Int, m: Int, order: BInt) {
        self.dst = dst
        self.messageExpansion = messageExpansion
        self.L = L
        self.m = m
        self.order = order
    }

    func process(_ message: Data, count: Int) throws -> [[BInt]] {
        let byteLen = count * m * L
        let uniformBytes = try messageExpansion.expandMessage(message, dst: dst, byteLen: byteLen)
        var u = [[BInt]](repeating: [BInt](repeating: BInt(0), count: m), count: count)

        for i in 0..<count {
            var e = [BInt](repeating: BInt(0), count: m)
            for j in 0..<m {
                let elmOffset = L * (j + i * m)
                let tv = uniformBytes.subdata(in: elmOffset..<(elmOffset + L))
                e[j] = BInt(magnitude: tv.bytes) % order
            }
            u[i] = e
        }

        return u
    }

}
