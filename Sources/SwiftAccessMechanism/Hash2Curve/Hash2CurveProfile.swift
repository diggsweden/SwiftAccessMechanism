//
//  Hash2CurveProfile.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-09.
//

import Foundation
import BigInt
import SwiftECC

public enum Hash2CurveProfile {

    case P256_XMD_SHA_256_SSWU_RO
    case P384_XMD_SHA_384_SSWU_RO
    case P521_XMD_SHA_512_SSWU_RO

    internal var cipherSuiteID: String {
        switch self {
        case .P256_XMD_SHA_256_SSWU_RO:
            return "P256_XMD:SHA-256_SSWU_RO_"
        case .P384_XMD_SHA_384_SSWU_RO:
            return "P384_XMD:SHA-384_SSWU_RO_"
        case .P521_XMD_SHA_512_SSWU_RO:
            return "P521_XMD:SHA-512_SSWU_RO_"
        }
    }

    var digest: DigestAlgorithm {
        switch self {
        case .P256_XMD_SHA_256_SSWU_RO:
            return SHA256Algorithm()
        case .P384_XMD_SHA_384_SSWU_RO:
            return SHA384Algorithm()
        case .P521_XMD_SHA_512_SSWU_RO:
            return SHA512Algorithm()
        }
    }

    internal var curve: Domain {
        switch self {
        case .P256_XMD_SHA_256_SSWU_RO:
            return Domain.instance(curve: .EC256r1)
        case .P384_XMD_SHA_384_SSWU_RO:
            return Domain.instance(curve: .EC384r1)
        case .P521_XMD_SHA_512_SSWU_RO:
            return Domain.instance(curve: .EC521r1)
        }
    }

    internal var Z: BInt {
        // Z is a constant used in the Simplified Shallue-van de Woestijne-Ulas (SSWU) map
        // to encode arbitrary inputs to points on an elliptic curve. It is defined
        // uniquely for each curve as per the Hash-to-Curve specification (RFC 9380).
        switch self {
        case .P256_XMD_SHA_256_SSWU_RO:
            return BInt("ffffffff00000001000000000000000000000000fffffffffffffffffffffff5", radix: 16)!
        case .P384_XMD_SHA_384_SSWU_RO:
            return BInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffff3", radix: 16)!
        case .P521_XMD_SHA_512_SSWU_RO:
            return BInt("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb", radix: 16)!
        }
    }

    internal var k: Int {
        // k is the security parameter that determines the length of the random
        // input to the hash-to-curve function. It is used to ensure sufficient
        // entropy in the hashing process, as specified in RFC 9380.
        switch self {
        case .P256_XMD_SHA_256_SSWU_RO:
            return 128
        case .P384_XMD_SHA_384_SSWU_RO:
            return 192
        case .P521_XMD_SHA_512_SSWU_RO:
            return 256
        }
    }

    internal var L: Int {
        // L is the length of the output from the hash-to-field function, which
        // is used as an intermediate step in the hash-to-curve process. It is
        // determined based on the elliptic curve's field size, as per RFC 9380.
        switch self {
        case .P256_XMD_SHA_256_SSWU_RO:
            return 48
        case .P384_XMD_SHA_384_SSWU_RO:
            return 72
        case .P521_XMD_SHA_512_SSWU_RO:
            return 98
        }
    }
}
