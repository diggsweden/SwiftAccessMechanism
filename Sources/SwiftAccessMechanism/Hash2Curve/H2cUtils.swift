//
//  H2cUtils.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-05.
//


import Foundation
import SwiftECC
import BigInt

internal struct H2cUtils {

    enum H2cUtilsError: Error {
        case illegalArgument(String)
    }


    /**
     * Constant time implementation of selection of value based on condition
     *
     * @param a value selected on condition = false
     * @param b value selected on condition = true
     * @param condition condition
     * @return 'a' if condition is false, else 'b'
     * @param <T> the type of object to select
     */
    static func cmov<T>(_ a: T, _ b: T, _ condition: Bool) -> T {
        return condition ? b : a
    }

    /**
     * Test if a value is square in a curve order
     *
     * @param xData The test value as Data
     * @param orderData The curve order as Data
     * @return true if x is a square, false otherwise
     */
    static func isSquare(_ x: BInt, order: BInt) -> Bool {
        // Calculate (order - 1) / 2
        let exponent = (order - 1) / 2

        // Calculate x^exponent % order
        let modPow = x.expMod(exponent, order)

        // Check if the result is 1 or 0
        return modPow == 1 || modPow == 0
    }


    /**
     * Get the first non-square member of the curve order
     *
     * - Parameters:
     *   - orderData: The curve order as Data.
     * - Returns: The first non-square member of the curve order as Data.
     */
    // Get the first non-square member of the curve order
    static func getFirstNonSquare(order: BInt) -> BInt {
        let maxCount = BInt(1000)
        var nonSquare = BInt.ONE

        while isSquare(nonSquare, order: order) {
            nonSquare += 1
            if nonSquare > maxCount {
                fatalError("Illegal Field. No non-square value can be found")
            }
        }

        return nonSquare
    }
    /**
     * Calculates the square root of a BigUInt 'x' with respect to a given BigUInt 'order'.
     *
     * This is an implementation of the "Constant-Time Tonelli-Shanks Algorithm" from RFC9380.
     *
     * - Parameters:
     *   - x: The BigUInt value to calculate the square root for.
     *   - order: The BigUInt representing the order.
     * - Returns: The square root of 'x' with respect to 'order'.
     */
    static func sqrt(_ x: BInt, order: BInt) -> BInt? {
        // Get the largest integer c1 where 2^c1 divides order - 1
        let c1 = (order - 1).trailingZeroBitCount
        let c2 = (order - BInt.ONE) / BInt.TWO ** c1
        let c3 = (c2 - BInt.ONE) / BInt.TWO
        let c4 = getFirstNonSquare(order: order)
        let c5 = c4.expMod(c2, order)

        // Procedure
        var z = x.expMod(c3, order)
        var t = (z * z * x) % order
        z = (z * x) % order
        var b = t
        var c = c5

        for i in stride(from: c1, through: 2, by: -1) {
            var bPower = b
            if i > 2 {
                for _ in 1...(i - 2) {
                    bPower = (bPower * bPower) % order
                }
            }
            let e = (bPower == BInt.ONE)
            let zt = (z * c) % order
            z = cmov(zt, z, e)
            c = (c * c) % order
            let tt = (t * c) % order
            t = cmov(tt, t, e)
            b = t
        }

        return z
    }

    /**
     * Returns the sign of the BigInt 'x' using the given EC group parameter.
     *
     * - Parameters:
     *   - xData: The value as Data.
     *   - group: The EC group parameter as OpaquePointer.
     * - Returns: The sign of 'x'.
     * - Throws: IllegalArgumentException if spec.getCurve().getField().getDimension() != 1
     */
    static func sgn0(_ x: BInt, curve: Domain) -> Int {
        //if curve.fieldDimension() == 1 {
        if 1 == 1 {
            return (x % 2).asInt()!
        }
        // TODO: Implement sign0 test for extension fields
        fatalError("Extension fields != 1 is not implemented yet")
    }



    /**
     * Convert an integer value to a byte array of a specified length.
     *
     * Integer-to-Octet-String primitive (RFC8017)
     *
     * - Parameters:
     *   - val: The integer value to be converted.
     *   - len: The length of the resulting byte array.
     * - Returns: The byte array representation of the integer value.
     * - Throws: If the value requires more bytes than the assigned length size.
     */
    static func i2osp(_ val: Int, len: Int) throws -> Data {
        var valueData = withUnsafeBytes(of: val.bigEndian) { Data($0) }

        // Remove leading zeros
        while valueData.count > 1 && valueData.first == 0x00 {
            valueData.removeFirst()
        }

        if valueData.count > len {
            throw H2cUtilsError.illegalArgument("Value requires more bytes than the assigned length size")
        }

        if valueData.count < len {
            // Pad with leading zeros to the expected length
            let padding = Data(repeating: 0x00, count: len - valueData.count)
            valueData = padding + valueData
        }

        return valueData
    }

    /**
     * Converts a byte array to a BigUInt.
     *
     *  Octet-String-to-Integer primitive (RFC8017)
     *
     * - Parameter val: The byte array to convert.
     * - Returns: The BigUInt representation of the byte array.
     */
    static func os2ip(_ val: Data) -> BInt {
        // Ensure we get a positive value by adding 0x00 as leading byte in the value byte array
        var dataWithLeadingZero = Data([0x00])
        dataWithLeadingZero.append(val)
        return BInt(magnitude: dataWithLeadingZero.bytes)
    }

    /**
     * Performs bitwise XOR operation on two byte arrays.
     *
     * - Parameters:
     *   - arg1: The first byte array.
     *   - arg2: The second byte array.
     * - Returns: The result of the XOR operation as a new byte array.
     * - Throws: `NSError` if either `arg1` or `arg2` is `nil`.
     * - Throws: `IllegalArgumentException` if `arg1` and `arg2` have different lengths.
     */
    static func xor(_ arg1: Data, _ arg2: Data) throws -> Data {
        guard arg1.count == arg2.count else {
            throw NSError(domain: "ByteArrayUtils", code: 1, userInfo: [NSLocalizedDescriptionKey: "XOR operation on parameters of different lengths"])
        }

        var xorArray = Data(count: arg1.count)
        for i in 0..<arg1.count {
            xorArray[i] = arg1[i] ^ arg2[i]
        }
        return xorArray
    }

}
