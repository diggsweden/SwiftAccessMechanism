//
//  XmdMessageExpansion.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-08.
//

import Foundation

internal class XmdMessageExpansion: MessageExpansionProtocol {

    enum xmdMessageError: Error {
        case illegalArgument(String)
    }

    let digestAlgo: DigestAlgorithm

    let s: Int

    let hashOutputBytes: Int

    init(digestAlgo: DigestAlgorithm, securityLevelBits k: Int) throws {
        self.digestAlgo = digestAlgo
        self.s = digestAlgo.inputBlockSize()
        self.hashOutputBytes = digestAlgo.digestSize()
        let requiredHashOutputBytes = Int(ceil(Double(k * 2) / 8.0))
        if self.hashOutputBytes < requiredHashOutputBytes {
            throw xmdMessageError.illegalArgument("Hash output size is too small for the security level of the curve")
        }
    }

    func expandMessage(_ msg: Data, dst: Data, byteLen: Int) throws -> Data {
        let ell = Int(ceil(Double(byteLen) / Double(hashOutputBytes)))
        if ell > 255 {
            throw xmdMessageError.illegalArgument("Ell parameter must not be greater than 255. Current value = \(ell)")
        }
        if byteLen > 65535 {
            throw xmdMessageError.illegalArgument("Output size must not be greater than 65535. Current value = \(byteLen)")
        }
        if dst.count > 255 {
            throw xmdMessageError.illegalArgument("DST size must not be greater than 255. Current value = \(dst.count)")
        }

        let dstPrime = try dst + H2cUtils.i2osp(dst.count, len: 1)
        let zPad = try H2cUtils.i2osp(0, len: s / 8)
        let libStr = try H2cUtils.i2osp(byteLen, len: 2)
        let msgPrime = try zPad + msg + libStr + H2cUtils.i2osp(0, len: 1) + dstPrime

        var b = [Data](repeating: Data(count: hashOutputBytes), count: ell + 1)
        b[0] = digestAlgo.hash(msgPrime)

        b[1] = try digestAlgo.hash(b[0] + H2cUtils.i2osp(1, len: 1) + dstPrime)
        var uniformBytes = b[1]

        for i in 2...ell {
            try b[i] = digestAlgo.hash(H2cUtils.xor(b[0], b[i - 1]) + H2cUtils.i2osp(i, len: 1) + dstPrime)
            uniformBytes.append(contentsOf: b[i])
        }
        return uniformBytes.prefix(byteLen)  }
}
