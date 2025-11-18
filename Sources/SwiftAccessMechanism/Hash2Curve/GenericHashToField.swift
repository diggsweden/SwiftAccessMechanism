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

    /// <#Description#>
    /// - Parameters:
    ///   - dst: Domain Separation Tag, separate usages cryptographically
    ///   - messageExpansion: <#messageExpansion description#>
    ///   - L: <#L description#>
    ///   - m: <#m description#>
    ///   - order: <#order description#>
    ///   - count: <#count description#>
    init(dst: Data, messageExpansion: MessageExpansionProtocol, L: Int, m: Int, order: BInt) {
        self.dst = dst
        self.messageExpansion = messageExpansion
        self.L = L
        self.m = m
        self.order = order
    }

    init(dst: Data, curve: Domain, digest: DigestAlgorithm, L: Int, securityLevelBits k: Int) throws {
        self.dst = dst
        self.L = L
        self.messageExpansion = try XmdMessageExpansion(digestAlgo: digest, securityLevelBits: k)
        self.m = curve.cofactor
        self.order = curve.order
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
