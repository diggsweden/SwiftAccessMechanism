//
//  Extensions.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-06.
//

import Foundation
import BigInt
import SwiftECC

// Extension to convert a hex string to Data
extension Data {
    init?(byteEncoded string: String) {
        let len = string.count / 2
        var data = Data(capacity: len)
        var index = string.startIndex
        for _ in 0..<len {
            let nextIndex = string.index(index, offsetBy: 2)
            if let b = UInt8(string[index..<nextIndex], radix: 16) {
                data.append(b)
            } else {
                return nil
            }
            index = nextIndex
        }
        self = data
    }
}

extension Data {
    func hexString(_ separator: String = "") -> String {
        return self.map { String(format: "%02hhx", $0) }.joined(separator: separator)
    }
}


extension Data {
    // Initialize Data from a integer hex string
    init?(bigIntHex hex: String) {
        self.init()

        var hexString = hex
        // Ensure the string has even length
        if hexString.count % 2 != 0 {
            hexString = "0" + hexString
        }

        for i in stride(from: 0, to: hexString.count, by: 2) {
            let startIndex = hexString.index(hexString.startIndex, offsetBy: i)
            let endIndex = hexString.index(startIndex, offsetBy: 2)
            let hexByte = String(hexString[startIndex..<endIndex])
            if let byte = UInt8(hexByte, radix: 16) {
                self.append(byte)
            } else {
                return nil
            }
        }
    }

    init(hex: String) {
        self.init(bigIntHex: hex)!
    }
}

extension BInt {
    func hexString(_ separator:String = "") -> String {
        // Convert BigUInt to Data
        let data = Data(self.asMagnitudeBytes())

        return data.hexString()
    }
}


extension Data {
    var bytes: [Byte] {
        var byteArray = [UInt8](repeating: 0, count: self.count)
        self.copyBytes(to: &byteArray, count: self.count)
        return byteArray
    }
}

extension Domain {
    /**
     * Calculates the size of the L parameter for an elliptic curve based on the given EC group and targetSecurityLevelBits.
     *
     * NOTE: We already have the L value for the implemented curves statically in Hash2CurveProfile.
     *
     * - Parameters:
     *   - targetSecurityLevelBits: The target security level in bits.
     * - Returns: The size of the L parameter in bytes.
     */
    func getCurveLsize(targetSecurityLevelBits: Int) -> Int {
        // Calculate the size of the L parameter in bytes
        let lSize = ceil(Double(self.p.bitWidth + targetSecurityLevelBits) / 8.0)
        return Int(lSize)
    }
}

extension Point {
    func hexString(_ curve: Domain, _ compress: Bool = true) -> String {
        do {
            return Data(try curve.encodePoint(self, compress)).hexString()
        } catch {
            return "ERROR"
        }
    }
}
