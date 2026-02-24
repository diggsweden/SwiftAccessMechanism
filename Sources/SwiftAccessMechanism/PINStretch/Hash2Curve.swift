//
//  Hash2Curve.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-26.
//
import Foundation

func h2c(input: Data) throws -> Data {
    return try hashToCurveP256Sha256(input: input, dst: "h2c-rust".data(using: .ascii)!)
}
