//
//  ECCurveProtocols.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-05.
//

import Foundation
import BigInt


public protocol ECPointProtocol {
    associatedtype PointType

    var value: PointType { get }
    var data: Data? { get }

    func cast<T>(to type: T.Type) -> T
}

public protocol ECCurveProtocol {
    associatedtype ECPoint: ECPointProtocol

    var description: String { get }
    var generator: ECPoint { get }

    /// Serialize a curve element (Point) using compressed point encoding.
    /// - Parameter element: The point to serialize.
    /// - Returns: The compressed encoded point as Data.
    func encodePoint(_ element: ECPoint, compress: Bool) throws -> Data

    /// Deserialize a serialized curve element (Data) into a Point.
    /// - Parameter data: The encoded point as Data (compressed or uncompressed bytes).
    /// - Returns: The decoded Point on the curve.
    func decodePoint(_ data: Data) throws -> ECPoint

    /// Multiplies a curve Point by an integer
    ///
    /// - Parameters:
    ///   - p: The curve point to multiply
    ///   - n: The integer to multiply with
    /// - Returns: n \* p
    /// - Throws: A `notOnCurve` exception if `p` is not on the curve
    func multiplyPoint(_ p: ECPoint, _ n: BInt) throws -> ECPoint

    func addPoints(_ p1: ECPoint, _ p2: ECPoint) throws -> ECPoint
}
