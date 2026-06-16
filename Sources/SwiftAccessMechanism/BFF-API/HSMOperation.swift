// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

import Foundation

public enum HSMOperation: String, Sendable {
    case registerPin
    case createSession
    case changePin
    case createKey
    case listKeys
    case sign
    case deleteKey
}
