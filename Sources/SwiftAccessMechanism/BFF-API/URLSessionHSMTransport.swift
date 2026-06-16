// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

import Foundation

/// Routes all signed JWT operations to `/hsm/v1/operations`.
/// The wallet app uses GatewayApiClient (in WalletGateway) instead.
public struct URLSessionHSMTransport: HSMTransport {
    private let baseUrl: String

    public init(baseUrl: String) {
        self.baseUrl = baseUrl
    }

    public func registerState(publicKey: JwkKey, overwrite: Bool, ttl: String?) async throws -> RegisterStateResponse {
        let body = NewStateRequest(publicKey: publicKey, clientId: nil, overwrite: overwrite, ttl: ttl)
        let data = try await post(path: "/hsm/v1/device-states", body: body)
        let response = try JSONDecoder().decode(NewStateResponse.self, from: data)
        guard response.status == .ok, let clientId = response.clientId else {
            throw TransportError.invalidResponse
        }
        return RegisterStateResponse(
            clientId: clientId,
            devAuthorizationCode: response.devAuthorizationCode,
            serverJwsPublicKey: response.serverJwsPublicKey,
            opaqueServerId: response.opaqueServerId
        )
    }

    public func perform(_ request: HSMRequest, operation: HSMOperation) async throws -> Data {
        try await post(path: "/hsm/v1/operations", body: request)
    }

    private func post<Body: Encodable>(path: String, body: Body) async throws -> Data {
        guard let url = URL(string: baseUrl + path) else { throw TransportError.invalidURL }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("*/*", forHTTPHeaderField: "Accept")
        urlRequest.httpBody = try JSONEncoder().encode(body)
        urlRequest.timeoutInterval = 30.0
        let (data, response) = try await URLSession.shared.data(for: urlRequest)
        guard let http = response as? HTTPURLResponse else { throw TransportError.networkError }
        guard 200...299 ~= http.statusCode else { throw TransportError.httpError(http.statusCode) }
        return data
    }

    public enum TransportError: Error {
        case invalidURL
        case networkError
        case httpError(Int)
        case invalidResponse
    }
}
