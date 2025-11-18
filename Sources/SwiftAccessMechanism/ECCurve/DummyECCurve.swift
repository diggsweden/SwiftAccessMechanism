//
//  DummyECCurve.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-05.
//

import Foundation
import BigInt

public struct DummyECCPoint: ECPointProtocol {
    public typealias PointType = Data

    fileprivate var _value: PointType

    public init(_ value: PointType) {
        self._value = value
    }

    public var value: PointType { return _value }

    public var data: Data? {
        return self._value
    }

    /// Attempts to cast the underlying value to a specific type
    public func cast<T>(to type: T.Type) -> T {
        return value as! T
    }
}

public struct DummyECCurve: ECCurveProtocol {
    public typealias ECPoint = DummyECCPoint

    public var description = "Dummy"
    public var generator = DummyECCPoint(Data())


    public func encodePoint(_ element: ECPoint, compress: Bool = true) throws -> Data {
        return element.data!
    }
    public func decodePoint(_ data: Data) throws -> ECPoint {
        return DummyECCPoint(data)
    }

    public func multiplyPoint(_ p: ECPoint, _ n: BInt) throws -> ECPoint {
        return p
    }

    public func addPoints(_ p1: ECPoint, _ p2: ECPoint) -> ECPoint {
        var res = p1.data ?? Data()
        res.append(p2.data ?? Data())
        return DummyECCPoint(res)
    }
}

func foo(p0: DummyECCPoint, p1: DummyECCPoint) -> DummyECCPoint {
    return DummyECCurve().addPoints(p0, p1)
}
