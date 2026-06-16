// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

import Foundation

public protocol HSMTransport: Sendable {
    func registerState(publicKey: JwkKey, overwrite: Bool, ttl: String?) async throws -> RegisterStateResponse
    @discardableResult
    func perform(_ request: HSMRequest, operation: HSMOperation) async throws -> Data
}
