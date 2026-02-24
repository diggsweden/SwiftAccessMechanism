# Testing

Test helpers, fixtures, and patterns for SwiftAccessMechanism.

## Overview

SwiftAccessMechanism uses **Swift Testing** framework (not XCTest). Tests cover unit operations and full integration flows.

## Running Tests

```bash
# All tests
swift test

# Specific test
swift test --filter SwiftAccessMechanismTests.testEcdsaSign

# Single test function
swift test --filter testListKeysAfterAuthentication
```

## Test Client

``BFFHttpClient/getTestClient(baseUrl:)`` provides a pre-configured client:

```swift
import SwiftAccessMechanism

var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")

// Includes:
// - Fixed P-256 test private key
// - Default ServerParameters (test server public key)
// - Standard test identifier (clientId)
// - Posts to {baseUrl}/r2ps-api/service
```

## Integration Tests

Integration tests require running service at `http://localhost:8088`. Tests gracefully skip on connection errors.

### Test Fixtures

Standard setup from `APIRequestTests`:

```swift
private static func setupClient() throws -> (api: BFFHttpClient, password: Data) {
    let baseUrl = "http://localhost:8088"
    let api = try BFFHttpClient.getTestClient(baseUrl: baseUrl)
    let password = "test".data(using: .utf8)!
    return (api, password)
}
```

### Full Flow (testEcdsaSign)

```swift
@Test func testEcdsaSign() async throws {
    var (api, password) = try Self.setupClient()

    do {
        // Register + authenticate
        _ = try await api.registration(password: password)
        _ = try await api.authenticate(password: password)

        // Create key
        let createdKey = try await api.createHsmKey()
        let key = createdKey.public_key

        // Sign
        let message = "test message".data(using: .utf8)!
        let digest = Data(SHA256.hash(data: message))
        let signatureResponse = try await api.sign(hsmKeyId: key.kid, digest: digest)

        // Verify (two ways)
        let signatureDER = try signatureResponse.toDER()
        let pub = try key.toSecKey()

        // Against digest
        var cfError: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(
            pub, .ecdsaSignatureDigestX962SHA256,
            digest as CFData, signatureDER as CFData, &cfError
        )
        #expect(verified == true)

        // Against raw message
        let verified2 = SecKeyVerifySignature(
            pub, .ecdsaSignatureMessageX962SHA256,
            message as CFData, signatureDER as CFData, &cfError
        )
        #expect(verified2 == true)

    } catch let urlError as URLError {
        switch urlError.code {
        case .cannotConnectToHost, .cannotFindHost,
             .networkConnectionLost, .notConnectedToInternet, .timedOut:
            return // Server not running, skip
        default:
            Issue.record("Unexpected: \(urlError)")
        }
    }
}
```

### List Keys (testListKeysAfterAuthentication)

```swift
@Test func testListKeysAfterAuthentication() async throws {
    var (api, password) = try Self.setupClient()

    do {
        _ = try await api.registration(password: password)
        let authResult = try await api.authenticate(password: password)

        #expect(authResult.response.outer.sessionId != nil)

        let listResponse = try await api.listKeys()
        #expect(listResponse.keyInfo.count >= 0)

    } catch let urlError as URLError {
        // ... skip on connection error
    }
}
```

### Create Key (testCreateKeyInHSM)

```swift
@Test func testCreateKeyInHSM() async throws {
    var (api, password) = try Self.setupClient()

    do {
        _ = try await api.registration(password: password)
        _ = try await api.authenticate(password: password)

        let beforeList = try await api.listKeys()
        let beforeCount = beforeList.keyInfo.count

        let createdKey = try await api.createHsmKey()

        let afterList = try await api.listKeys()
        #expect(afterList.keyInfo.count >= beforeCount + 1)
        #expect(afterList.keyInfo[0].publicKey.kid == createdKey.public_key.kid)

    } catch let urlError as URLError {
        // ... skip on connection error
    }
}
```

## Connection Error Pattern

All integration tests use this pattern to skip gracefully:

```swift
do {
    // ... test operations ...
} catch let urlError as URLError {
    switch urlError.code {
    case .cannotConnectToHost, .cannotFindHost,
         .networkConnectionLost, .notConnectedToInternet, .timedOut:
        print("Server not running, skipping")
        return
    default:
        Issue.record("Unexpected network error: \(urlError)")
    }
} catch {
    Issue.record("Unexpected error: \(error)")
}
```

## Test Organization

Tests in `Tests/SwiftAccessMechanismTests/`:

- `APIRequestTests.swift` — Integration tests (require localhost:8088)
  - `testCreateSessionWithRequestObject` — Register + authenticate
  - `testListKeysAfterAuthentication` — List keys
  - `testCreateKeyInHSM` — Create key + verify count
  - `testEcdsaSign` — Full sign + verify flow
- `SwiftAccessMechanismTests.swift` — Unit tests

## Debugging Tests

```bash
# Verbose output
swift test --verbose

# Single test with output
swift test --filter testEcdsaSign --verbose
```

## See Also

- <doc:Getting-Started> — Integration examples
- <doc:Error-Handling> — Error testing patterns
- ``BFFHttpClient/getTestClient(baseUrl:)`` — Test client setup
