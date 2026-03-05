// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

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
