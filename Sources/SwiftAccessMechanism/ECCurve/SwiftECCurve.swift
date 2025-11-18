//
//  SwiftECCCurve.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-03.
//

import Foundation
import SwiftECC
import BigInt

public struct SwiftECCPoint: ECPointProtocol {
    public typealias PointType = Point

    fileprivate var _value: PointType

    public init(_ value: PointType) {
        self._value = value
    }

    public var value: PointType { return _value }

    public var data: Data? {
        do {
            return self.cast(to: Data.self)
        } catch {
            return nil
        }
    }

    /// Attempts to cast the underlying value to a specific type
    public func cast<T>(to type: T.Type) -> T {
        return value as! T
    }
}


public struct SwiftECCurve: ECCurveProtocol {
    public typealias ECPoint = SwiftECCPoint

    public var description: String = "SwiftECC"
    public var generator: ECPoint

    enum SwiftECCurveError: Error {
        case invalidInputError
    }

    private let domain: Domain

    public init(domain: Domain) {
        self.domain = domain
        self.generator = SwiftECCPoint(domain.g)
    }

    /// Serialize a curve element (Point) using compressed point encoding.
    /// - Parameter element: The point to serialize.
    /// - Returns: The compressed encoded point as Bytes.
    public func encodePoint(_ element: ECPoint, compress: Bool = true) throws -> Data {
        let result = try self.domain.encodePoint(element.value, compress)
        return Data(result)
    }

    /// Deserialize a serialized curve element (Data) into a Point.
    /// - Parameter data: The encoded point as Data (compressed or uncompressed bytes).
    /// - Returns: The decoded Point on the curve.
    public func decodePoint(_ data: Data) throws -> ECPoint {
        let curve = self.domain
        let element = try curve.decodePoint([UInt8](data))
        if element.infinity {
            throw SwiftECCurveError.invalidInputError
        }
        return SwiftECCPoint(element)
    }

    /// Multiplies a curve Point by an integer
    ///
    /// - Parameters:
    ///   - p: The curve point to multiply
    ///   - n: The integer to multiply with
    /// - Returns: n * p
    /// - Throws: A `notOnCurve` exception if `p` is not on the curve
    public func multiplyPoint(_ point: ECPoint, _ n: BInt) throws -> ECPoint {
        let res = try domain.multiplyPoint(point.value, n)
        return SwiftECCPoint(res)
    }

    public func addPoints(_ p1: ECPoint, _ p2: ECPoint) throws -> ECPoint {
        let res = try domain.addPoints(p1.value, p2.value)
        return SwiftECCPoint(res)
    }
}
