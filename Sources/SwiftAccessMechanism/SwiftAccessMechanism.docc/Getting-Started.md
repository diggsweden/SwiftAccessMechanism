# Getting Started

Complete guide to integrating SwiftAccessMechanism for OPAQUE authentication and HSM key operations.

## Prerequisites

**OpaqueKeUniffi.xcframework** (Rust OPAQUE implementation):
1. Build from https://github.com/diggsweden/opaque_ke_uniffi/
2. Place in `external/OpaqueKeUniffi.xcframework/`
3. Project references it as binary target in Package.swift

## Installation

Add to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/diggsweden/SwiftAccessMechanism", from: "1.0.0")
]
```

## Build & Test

```bash
swift build          # Build library
swift test           # Run all tests
swift test --filter SwiftAccessMechanismTests.testEcdsaSign  # Single test
```

Integration tests require a running HTTP REST API backend at `http://localhost:8088`.

## Complete Example

Full registration, authentication, key creation, signing, and verification flow.
Based on `testEcdsaSign` integration test:

```swift
import SwiftAccessMechanism
import CryptoKit

// Initialize test client (includes server public key + OPAQUE params)
// `var` required because authenticate() is mutating
var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")
let password = "user-pin".data(using: .utf8)!

// Step 1: Register (one-time OPAQUE setup)
_ = try await client.registration(password: password)

// Step 2: Authenticate (OPAQUE start + finish, establishes session)
// After this call, client is in session mode with symmetric encryption
let authResult = try await client.authenticate(password: password)

// Step 3: Create an HSM key (P-256)
let createdKey = try await client.createHsmKey()
let key = createdKey.public_key
print("Created key: \(key.kid)")

// Step 4: List keys to verify
let listResponse = try await client.listKeys()
for keyInfo in listResponse.keyInfo {
    print("Key: \(keyInfo.kid), Created: \(keyInfo.createdAt)")
}

// Step 5: Sign a SHA-256 digest with the HSM key
let message = "Hello, EUDI Wallet!".data(using: .utf8)!
let digest = Data(SHA256.hash(data: message))
let signatureResponse = try await client.sign(
    hsmKeyId: key.kid,
    digest: digest
)

// Step 6: Verify signature locally
// verifySignature() throws SignatureVerificationError.invalidSignature on failure
try verifySignature(publicKey: key, signature: signatureResponse, digest: digest)
print("Signature verified!")
```

## PIN Stretching

In production, use ``PINStretch`` to strengthen the user's PIN before OPAQUE:

```swift
// PINStretch is a struct that initializes a Secure Enclave key
let pinStretch = PINStretch()
let password = try pinStretch.stretch(input: "1234".data(using: .utf8)!)

// Use stretched password with OPAQUE
_ = try await client.registration(password: password)
_ = try await client.authenticate(password: password)
```

``PINStretch/stretch(input:)`` converts a weak PIN to a 32-byte key via ECDH with a Secure Enclave key. See <doc:PIN-Stretching> for details.

## Production Setup

For production, provide real ``ServerParameters``:

```swift
let serverParams = try ServerParameters(
    serverPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----",
    opaqueContext: Data("EUDI-Wallet-Production".utf8),
    opaqueServerIdentifier: Data("eudi.example.com".utf8)
)

let client = try BFFHttpClient(
    clientPrivateKey: privateKey,
    serverParameters: serverParams,
    baseUrl: "https://eudi.example.com",
    clientId: clientId
)
```

## Error Handling

```swift
do {
    _ = try await client.authenticate(password: password)
} catch let error as BFFHttpClient.APIError {
    switch error {
    case .parameterError:
        print("Invalid base URL")
    case .httpError(let statusCode):
        print("Server returned HTTP \(statusCode)")
    case .networkError:
        print("Network unavailable")
    }
} catch let urlError as URLError {
    switch urlError.code {
    case .cannotConnectToHost, .cannotFindHost, .timedOut:
        print("Server unavailable: \(urlError.localizedDescription)")
    default:
        print("Network error: \(urlError)")
    }
}
```

See <doc:Error-Handling> for comprehensive error handling patterns.

## Signature Verification

Two approaches for verifying HSM signatures:

**Using `verifySignature()` helper (throws on failure):**

```swift
// Takes JwkKey + SignatureResponse directly, verifies against SHA-256 digest
try verifySignature(publicKey: key, signature: signatureResponse, digest: digest)
```

**Using SecKey directly:**

```swift
let secKey = try key.toSecKey()
let derSig = try signatureResponse.toDER()

// Verify against pre-hashed digest
let valid = SecKeyVerifySignature(
    secKey,
    .ecdsaSignatureDigestX962SHA256,
    digest as CFData,
    derSig as CFData,
    nil
)

// Or verify against raw message (Security framework does the hashing)
let valid2 = SecKeyVerifySignature(
    secKey,
    .ecdsaSignatureMessageX962SHA256,
    message as CFData,
    derSig as CFData,
    nil
)
```

## Next Steps

- Read <doc:Architecture> to understand the protocol stack design
- Explore <doc:Protocol-Layer> to use the stable core API directly
- Learn about <doc:Session-Lifecycle> (device mode → session mode)
- Review <doc:PIN-Stretching> for Secure Enclave integration
