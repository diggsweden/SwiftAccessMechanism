//
//  SqrtRatioCalculator.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-09.
//

import Foundation
import BigInt

internal class SqrtRatioCalculator: SqrtRatioProtocol {

    fileprivate let q: BInt
    fileprivate let z: BInt
    fileprivate let c1: Int
    fileprivate let c2: BInt
    fileprivate let c3: BInt
    fileprivate let c4: BInt
    fileprivate let c5: BInt
    fileprivate let c6: BInt
    fileprivate let c7: BInt

    init(field_order q: BInt, Z_constant z: BInt) {
        self.q = q
        self.z = z
        self.c1 = SqrtRatioCalculator.calculateC1(q: q)
        self.c2 = (q - 1) / (BInt(2) ** c1)
        self.c3 = (c2 - 1) / 2
        self.c4 = BInt(2) ** c1 - 1
        self.c5 = BInt(2) ** c1 - 1
        self.c6 = z.expMod(c2, q)
        self.c7 = z.expMod((c2 + 1) / 2, q)
    }

    fileprivate static func calculateC1(q: BInt) -> Int {
        var qMinusOne = q - 1
        var c1 = 0
        while qMinusOne % 2 == 0 {
            qMinusOne /= 2
            c1 += 1
        }
        return c1
    }

    func sqrtRatio(u: BInt, v: BInt) -> SqrtRatio {
        var tv1 = c6
        var tv2 = v.expMod(c4, q)
        var tv3 = tv2.expMod(BInt.TWO, q)
        tv3 = (tv3 * v) % q
        var tv5 = (u * tv3) % q
        tv5 = tv5.expMod(c3, q)
        tv5 = (tv5 * tv2) % q
        tv2 = (tv5 * v) % q
        tv3 = (tv5 * u) % q
        var tv4 = (tv3 * tv2) % q
        tv5 = tv4.expMod(c5, q)
        let isQR = (tv5 == 1)
        tv2 = (tv3 * c7) % q
        tv5 = (tv4 * tv1) % q
        tv3 = H2cUtils.cmov(tv2, tv3, isQR)
        tv4 = H2cUtils.cmov(tv5, tv4, isQR)

        for i in stride(from: c1, to: 1, by: -1) {
            tv5 = BInt(2) ** (i - 2)
            tv5 = tv4.expMod(tv5, q)
            let e1 = (tv5 == 1)
            tv2 = (tv3 * tv1) % q
            tv1 = (tv1 * tv1) % q
            tv5 = (tv4 * tv1) % q
            tv3 = H2cUtils.cmov(tv2, tv3, e1)
            tv4 = H2cUtils.cmov(tv5, tv4, e1)
        }

        return SqrtRatio(isQR: isQR, ratio: tv3)
    }
}
