//
//  Protocols.swift
//  SwiftAccessMechanism
//
//  Created by Stefan Santesson on 2024-07-08.
//

import Foundation
import BigInt
import SwiftECC

public protocol HashToFieldProtocol {

    //    hash_to_field(msg, count)
    //
    //    Input:
    //    - msg, a byte string containing the message to hash.
    //    - count, the number of elements of F to output.
    //
    //    Output:
    //    - (u_0, ..., u_(count - 1)), a list of field elements.
    //
    //    Steps: defined in Section 5.

    /// The `hash_to_field` function hashes a byte string msg of arbitrary length into one or more elements of a field 𝔽.
    /// - Parameters:
    ///   - message: the message to hash
    ///   - count: the number of elements of F to output
    /// - Returns: (u_0, ..., u_(count - 1)), a list of field elements
    func process(_ message: Data, count: Int) throws -> [[BInt]]
}


public protocol MapToCurveProtocol {

    //    map_to_curve(u)
    //
    //    Input: u, an element of field F.
    //    Output: Q, a point on the elliptic curve E.
    //    Steps: defined in Section 6.

    func process(_ element: BInt) throws -> Point

}


public protocol MessageExpansionProtocol {

    //    expand_message_xmd(msg, DST, len_in_bytes)
    //
    //    Parameters:
    //    - H, a hash function (see requirements above).
    //    - b_in_bytes, b / 8 for b the output size of H in bits.
    //      For example, for b = 256, b_in_bytes = 32.
    //    - s_in_bytes, the input block size of H, measured in bytes (see
    //      discussion above). For example, for SHA-256, s_in_bytes = 64.
    //
    //    Input:
    //    - msg, a byte string.
    //    - DST, a byte string of at most 255 bytes.
    //      See below for information on using longer DSTs.
    //    - len_in_bytes, the length of the requested output in bytes,
    //      not greater than the lesser of (255 * b_in_bytes) or 2^16-1.
    //
    //    Output:
    //    - uniform_bytes, a byte string.

    /// <#Description#>
    /// - Parameters:
    ///   - msg: <#msg description#>
    ///   - dst: <#dst description#>
    ///   - byteLen: <#byteLen description#>
    /// - Returns: <#description#>
    func expandMessage(_ msg: Data, dst: Data, byteLen: Int) throws -> Data

}

public protocol SqrtRatioProtocol {

    func sqrtRatio(u: BInt, v: BInt) -> SqrtRatio

}


public struct SqrtRatio {

    let isQR: Bool
    let ratio: BInt

}
