//
//  Extensions.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-17.
//
import Foundation

extension Data {
    func hexString(_ separator: String = "") -> String {
        return self.map { String(format: "%02hhx", $0) }.joined(separator: separator)
    }
}

