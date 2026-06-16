// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

import Foundation

public struct RegisterStateResponse: Sendable {
    public let clientId: String
    public let devAuthorizationCode: String?
    public let serverJwsPublicKey: JwkKey?
    public let opaqueServerId: String?

    public init(clientId: String, devAuthorizationCode: String?, serverJwsPublicKey: JwkKey? = nil, opaqueServerId: String? = nil) {
        self.clientId = clientId
        self.devAuthorizationCode = devAuthorizationCode
        self.serverJwsPublicKey = serverJwsPublicKey
        self.opaqueServerId = opaqueServerId
    }
}
