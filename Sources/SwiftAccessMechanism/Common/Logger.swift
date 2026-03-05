// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

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
    static let authn = Logger(subsystem: subsystem, category: "Authn")
    static let api = Logger(subsystem: subsystem, category: "API")
    static let sec = Logger(subsystem: subsystem, category: "Security")
}
