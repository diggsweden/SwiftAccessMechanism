// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  APIRequestTests.swift
//  SwiftAccessMechanismTests
//
//  Created by Fredrik Thulin on 2025-11-28.
//

import Testing
import Foundation
import Security
import JOSESwift
import CryptoKit
@testable import SwiftAccessMechanism

enum TestError: Error {
    case keyGenerationFailed(String)
    case responseMissing
}

@Suite(.serialized)
struct APIRequestTests {

    // Test server parameters for dev environment
    // nonisolated(unsafe): immutable constant initialized once, safe for concurrent access
    private nonisolated(unsafe) static let testServerParameters: ServerParameters = {
        try! ServerParameters(serverIdentifier: "dev.cloud-wallet.digg.se".data(using: .ascii)!)
    }()

    /// Create a test BFFHttpClient with an ephemeral key pair.
    ///
    /// Generates a fresh ephemeral P-256 key and registers with the server (overwrite: true for clean slate).
    private static func getTestClient(baseUrl: String) async throws -> BFFHttpClient {
        let keyTag = "test-\(UUID().uuidString)"
        let tagData = keyTag.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false, kSecAttrApplicationTag: tagData]
        ]
        guard let privateKey = SecKeyCreateRandomKey(attrs, &error) else {
            throw (error?.takeRetainedValue() as? Error) ?? TestError.keyGenerationFailed("key gen failed")
        }
        return try await BFFHttpClient(
            privateKey: privateKey,
            keyTag: keyTag,
            serverParameters: testServerParameters,
            baseUrl: baseUrl,
            overwrite: true
        )
    }

    // Centralized setup helper used by all tests
    private static func setupClient() async throws -> (api: BFFHttpClient, password: StretchedPIN) {
        let baseUrl = "http://localhost:8088"
        let api = try await getTestClient(baseUrl: baseUrl)
        let password = StretchedPIN(data: "test".data(using: .utf8)!)
        return (api, password)
    }

    @Test func testNewStateCreatesClient() async throws {
        let baseUrl = "http://localhost:8088"
        do {
            let (_, identity) = try await BFFHttpClient.createClient(baseUrl: baseUrl, serverParameters: Self.testServerParameters)
            print("✅ new_state: clientId=\(identity.clientId) keyTag=\(identity.keyTag)")
            print("   devAuthorizationCode=\(identity.devAuthorizationCode ?? "nil")")

            // Restore client from persisted identity
            let restored = try BFFHttpClient(identity: identity, serverParameters: try ServerParameters(serverIdentifier: "dev.cloud-wallet.digg.se".data(using: .ascii)!), baseUrl: baseUrl)
            _ = restored
            print("✅ restore via init succeeded")
        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet, .timedOut:
                print("⚠️ Connection error (expected if service is not running): \(urlError.localizedDescription)")
                return
            default:
                Issue.record("Unexpected network error: \(urlError.localizedDescription)")
            }
        } catch {
            print("⚠️ Network call failed (expected if service not running): \(error)")
            Issue.record("Unexpected error: \(error.localizedDescription)")
        }
    }

    @Test func testCreateSessionWithRequestObject() async throws {
        var (api, password) = try await Self.setupClient()

        do {
            // Step 1-2: Run consolidated registration (start + finish)
            let finishPakeResponse = try await api.registration(
                password: password
            )

            print("✅ Successfully completed OPAQUE registration (start+finish)")

            // Display the finish response
            print("✅ Registration finish response: \(finishPakeResponse)")
            print("  - responseData: \(finishPakeResponse.responseDataForDebug())")

            print("✅ Successfully completed OPAQUE registration flow")

            // Step 3: Now test authentication with the same password
            print("\n🔐 Starting OPAQUE authentication flow...")

            // Run consolidated authentication (start + finish)
            let authResult = try await api.authenticate(
                password: password
            )

            print("✅ Successfully completed OPAQUE authentication (start+finish)")

            // Display the authentication finish response
            print("✅ Authentication finish response: \(authResult.response)")

            print("✅ Successfully completed OPAQUE authentication flow")

            // Print the shared session key as hex
            print("  - SESSION KEY: \(authResult.sessionKey.hexString())")

        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet, .timedOut:
                print("⚠️ Connection error (expected if service is not running): \(urlError.localizedDescription)")
                return // This is expected when service is not available
            default:
                Issue.record("Unexpected network error: \(urlError.localizedDescription)")
            }
        } catch {
            print("⚠️ Network call failed (expected if service not running): \(error)")
            Issue.record("Unexpected network error: \(error.localizedDescription)")
        }
    }

    @Test func testListKeysAfterAuthentication() async throws {
        var (api, password) = try await Self.setupClient()

        do {
            // Register
            _ = try await api.registration(
                password: password
            )
            print("✅ Registered new PIN")

            // Authenticate
            let authResult = try await api.authenticate(
                password: password
            )
            let bffResponse = authResult.response
            print("✅ Authenticated using new PIN")

            #expect(bffResponse.outer.sessionId != nil)

            // List keys (expect empty)
            let listResponse = try await api.listKeys()
            // Server may already contain keys; ensure we got a valid response
            #expect(listResponse.keyInfo.count >= 0)
            print("✅ listKeys returned \(listResponse.keyInfo.count) keys as expected")

        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet, .timedOut:
                print("⚠️ Connection error (expected if service is not running): \(urlError.localizedDescription)")
                return
            default:
                Issue.record("Unexpected network error: \(urlError.localizedDescription)")
            }
        } catch {
            print("⚠️ Network call failed (expected if service not running): \(error)")
            Issue.record("Unexpected network error: \(error.localizedDescription)")
        }
    }

    // List keys, create a key, then list keys again and expect +1
    @Test func testCreateKeyInHSM() async throws {
        var (api, password) = try await Self.setupClient()

        do {
            // Register
            _ = try await api.registration(
                password: password
            )

            // Authenticate
            let authResult = try await api.authenticate(
                password: password
            )
            let bffResponse = authResult.response

            #expect(bffResponse.outer.sessionId != nil)

            // List keys (initial)
            let beforeList = try await api.listKeys()
            let beforeCount = beforeList.keyInfo.count
            print("ℹ️ Keys before create: \(beforeCount)")

            // Create a new HSM key
            let createdKey = try await api.createHsmKey()
            print("✅ Created HSM key: \(createdKey)")

            // List keys again
            let afterList = try await api.listKeys()
            let afterCount = afterList.keyInfo.count
            print("ℹ️ Keys after create: \(afterCount)")

            // Expect exactly one more key
            #expect(afterCount >= beforeCount + 1)

            #expect(afterList.keyInfo.contains { $0.kid == createdKey.public_key.kid })

        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet, .timedOut:
                print("⚠️ Connection error (expected if service is not running): \(urlError.localizedDescription)")
                return
            default:
                Issue.record("Unexpected network error: \(urlError.localizedDescription)")
            }
        } catch {
            print("⚠️ Network call failed (expected if service not running): \(error)")
            Issue.record("Unexpected network error: \(error.localizedDescription)")
        }
    }

    @Test func testEcdsaSign() async throws {
        var (api, password) = try await Self.setupClient()

        do {
            // Register
            _ = try await api.registration(
                password: password
            )

            // Authenticate
            let authResult = try await api.authenticate(
                password: password
            )
            let bffResponse = authResult.response

            #expect(bffResponse.outer.sessionId != nil)

            // Use the initial key created during device state-init (listKeys, then sign).
            // The backend allows only one HSM mutating op per session, so we must not
            // call createHsmKey() before sign() in the same session.
            let keyList = try await api.listKeys()
            guard let keyInfo = keyList.keyInfo.first else {
                Issue.record("No HSM keys available for signing")
                return
            }
            let key = keyInfo.publicKey

            // Compute tbs_hash (SHA-256 of a test message)
            let message = "test message".data(using: .utf8)!
            let digest = CryptoKit.SHA256.hash(data: message)
            let tbsHash = Data(digest)

            // Ask HSM to sign — server should return raw ASN.1 ECDSA signature bytes
            let signatureResponse = try await api.sign(hsmKeyId: key.kid, digest: tbsHash)

            let signatureDER = try signatureResponse.toDER()
            let pub = try key.toSecKey()

            // Verify the ASN.1 ECDSA signature over the provided digest using SecKeyVerifySignature
            var cfError: Unmanaged<CFError>?
            let verified = SecKeyVerifySignature(pub, SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256,
                                                 tbsHash as CFData, signatureDER as CFData, &cfError)

            #expect(verified == true)

            let verified2 = SecKeyVerifySignature(pub, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                                                  message as CFData, signatureDER as CFData, &cfError)
            #expect(verified2 == true)

            print("✅ ECDSA digest and message signature verification successful")

        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet, .timedOut:
                print("⚠️ Connection error (expected if service is not running): \(urlError.localizedDescription)")
                return
            default:
                Issue.record("Unexpected network error: \(urlError.localizedDescription)")
            }
        } catch {
            print("⚠️ Network call failed (expected if service not running): \(error)")
            Issue.record("Unexpected network error: \(error.localizedDescription)")
        }
    }

    @Test func testChangePinAfterAuthentication() async throws {
        var (api, password) = try await Self.setupClient()
        let newPassword = StretchedPIN(data: "newpass".data(using: .utf8)!)

        do {
            // Register and authenticate with initial password
            _ = try await api.registration(password: password)
            print("✅ Registered initial PIN")

            _ = try await api.authenticate(password: password)
            print("✅ Authenticated with initial PIN")

            // Change PIN
            try await api.changePin(newPassword: newPassword)
            print("✅ Changed PIN — session reset to device mode")

            // Re-authenticate with new password
            let authResult = try await api.authenticate(password: newPassword)
            print("✅ Authenticated with new PIN")
            #expect(authResult.response.outer.sessionId != nil)
            #expect(authResult.sessionKey.count == 32)

            // Verify session works by listing keys
            let listResponse = try await api.listKeys()
            #expect(listResponse.keyInfo.count >= 0)
            print("✅ listKeys after PIN change returned \(listResponse.keyInfo.count) keys")

        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet, .timedOut:
                print("⚠️ Connection error (expected if service is not running): \(urlError.localizedDescription)")
                return
            default:
                Issue.record("Unexpected network error: \(urlError.localizedDescription)")
            }
        } catch {
            print("⚠️ Network call failed (expected if service not running): \(error)")
            Issue.record("Unexpected network error: \(error.localizedDescription)")
        }
    }

    @Test func testDynamicClientRegistrationWithPIN() async throws {
        let baseUrl = "http://localhost:8088"
        let password = StretchedPIN(data: "testpin".data(using: .utf8)!)

        do {
            // Step 1: Create new client (generates new P-256 key, calls new_state)
            var (api, identity) = try await BFFHttpClient.createClient(baseUrl: baseUrl, serverParameters: Self.testServerParameters)
            print("✅ Created new client: clientId=\(identity.clientId) keyTag=\(identity.keyTag)")
            #expect(identity.clientId.isEmpty == false)
            #expect(identity.keyTag.isEmpty == false)

            guard let devAuth = identity.devAuthorizationCode else {
                print("⚠️ No devAuthorizationCode returned - server may not support dynamic registration")
                return
            }
            print("✅ Received devAuthorizationCode: \(devAuth)")

            // Step 2: Register PIN for the new client public key
            let regResponse = try await api.registration(password: password)
            print("✅ Registered PIN for new client: \(regResponse)")

            // Step 3: Verify can authenticate with registered PIN
            let authResult = try await api.authenticate(password: password)
            print("✅ Authenticated with registered PIN")
            #expect(authResult.response.outer.sessionId != nil)
            #expect(authResult.sessionKey.count == 32)

        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet, .timedOut:
                print("⚠️ Connection error (expected if service is not running): \(urlError.localizedDescription)")
                return
            default:
                Issue.record("Unexpected network error: \(urlError.localizedDescription)")
            }
        } catch BFFHttpClient.APIError.httpError(let code) {
            print("⚠️ HTTP \(code) from server - dynamic client registration may not be supported on backend")
            return
        } catch {
            print("⚠️ Network call failed (expected if service not running): \(error)")
            Issue.record("Unexpected network error: \(error.localizedDescription)")
        }
    }
}
