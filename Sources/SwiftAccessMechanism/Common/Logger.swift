//
//  Logger.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-17.
//
import OSLog

/// Set up subsystem loggers to be able to filter messages
extension Logger {
    private static let subsystem = "se.digg.wallet.AccessMechanism"

    static let opaque = Logger(subsystem: subsystem, category: "Opaque")
    static let sec = Logger(subsystem: subsystem, category: "SecureEnclave")
    static let authn = Logger(subsystem: subsystem, category: "Authn")
}

