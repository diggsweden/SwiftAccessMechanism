//
//  SVDWostijneMapToCurve.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-08.
//

import Foundation
import BigInt
import SwiftECC

internal class SVDWostijneMapToCurve: MapToCurveProtocol {

    let sqrtRatioCalculator: SqrtRatioProtocol
    let Z: BInt
    let curve: Domain

    init(curve: Domain, ecCurve: ECCurveProtocol, Z_constant Z: BInt) {
        self.Z = Z
        self.sqrtRatioCalculator = SqrtRatioCalculator(field_order: curve.p, Z_constant: Z)
        self.curve = curve
    }

    func process(_ u: BInt) throws -> Point {
        let A = curve.a
        let B = curve.b
        let p = curve.p

        var tv1 = u.expMod(BInt.TWO, p)
        tv1 = (Z * tv1) % p
        var tv2 = tv1.expMod(BInt.TWO, p)
        tv2 = (tv2 + tv1) % p
        var tv3 = (tv2 + 1) % p
        tv3 = (B * tv3) % p
        var tv4 = H2cUtils.cmov(Z, p - tv2, tv2 != 0)
        tv4 = (A * tv4) % p
        tv2 = tv3.expMod(BInt.TWO, p)
        var tv6 = tv4.expMod(BInt.TWO, p)
        var tv5 = (A * tv6) % p
        tv2 = (tv2 + tv5) % p
        tv2 = (tv2 * tv3) % p
        tv6 = (tv6 * tv4) % p
        tv5 = (B * tv6) % p
        tv2 = (tv2 + tv5) % p
        var x = (tv1 * tv3) % p
        let sqrtRatio = sqrtRatioCalculator.sqrtRatio(u: tv2, v: tv6)
        let isGx1Square = sqrtRatio.isQR
        let y1 = sqrtRatio.ratio
        var y = (tv1 * u) % p
        y = (y * y1) % p
        x = H2cUtils.cmov(x, tv3, isGx1Square)
        y = H2cUtils.cmov(y, y1, isGx1Square)
        let e1 = H2cUtils.sgn0(u, curve: curve) == H2cUtils.sgn0(y, curve: curve)
        y = H2cUtils.cmov(p - y, y, e1)

        // Correct the modular inverse operation
        if let invTv4 = modularInverse(tv4, modulus: p) {
            x = (x * invTv4) % p
        } else {
            throw Hash2CurveError.invalidInput
        }
        return Point(x, y)
    }

    func modularInverse(_ value: BInt, modulus: BInt) -> BInt? {
        // if value and modulus aren't coprime, return nil
        // TODO: Verify the BigInt implementation handles this for us.
        return value.modInverse(modulus)
    }

}
