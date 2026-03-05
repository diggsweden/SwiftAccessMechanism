// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  Extensions.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-17.
//
import Foundation
import JOSESwift


extension Data {
    /// Returns hex-encoded string representation of the data bytes.
    func hexString(_ separator: String = "") -> String {
        return self.map { String(format: "%02hhx", $0) }.joined(separator: separator)
    }
}
