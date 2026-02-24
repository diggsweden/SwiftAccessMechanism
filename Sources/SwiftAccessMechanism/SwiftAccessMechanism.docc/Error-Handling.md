# Error Handling

Guide to error types and recovery patterns.

## Error Types Overview

| Error Type | Thrown By | Typical Scenarios |
|------------|-----------|-------------------|
| `BFFHttpClient.APIError` | ``BFFHttpClient`` | Bad URL, HTTP errors, unparseable response |
| `BFFLayer.APIError` | ``BFFLayer`` | Similar + invalid signature, unexpected encryption |
| `ProtocolSession.Errors` | Protocol layer | Key parse failures, invalid session key |
| ``OpaqueClientError`` | ``OpaqueClient`` | OPAQUE protocol failures |
| ``PINStretchError`` | ``PINStretch`` | Secure Enclave unavailable, no key |
| `SignatureVerificationError` | `verifySignature()` | Invalid ECDSA signature |
| `OuterResponse.Error` | ``OuterResponse`` | Invalid JWS signature, decoding error |
| `URLError` | `URLSession` | Network failures (timeout, no connection) |

## BFFHttpClient.APIError

```swift
enum APIError: Error {
    case parameterError   // Invalid base URL
    case networkError     // Response not HTTPURLResponse
    case httpError(Int)   // Non-200 status code
}
```

### Usage

```swift
do {
    _ = try await client.authenticate(password: password)
} catch let error as BFFHttpClient.APIError {
    switch error {
    case .parameterError:
        print("Check base URL configuration")
    case .httpError(let statusCode):
        switch statusCode {
        case 400: print("Bad request")
        case 401: print("Authentication failed")
        case 500...599: print("Server error, retry later")
        default: print("HTTP \(statusCode)")
        }
    case .networkError:
        print("Response not HTTP")
    }
}
```

### Network Errors (URLError)

Network-level errors come through as `URLError`, not `APIError`:

```swift
do {
    _ = try await client.authenticate(password: password)
} catch let urlError as URLError {
    switch urlError.code {
    case .cannotConnectToHost, .cannotFindHost:
        print("Server unreachable")
    case .notConnectedToInternet:
        print("No internet connection")
    case .timedOut:
        print("Request timed out")
    default:
        print("Network error: \(urlError.localizedDescription)")
    }
}
```

This is the pattern used by all integration tests — see `testCreateSessionWithRequestObject`.

## ProtocolSession.Errors

```swift
enum Errors: Error {
    case signerCreationFailed
    case serverKeyParseError
    case clientKeyParseError
    case invalidSessionKey
    case failedToCreateDirectDecrypter
}
```

### Init Errors (Device Mode)

```swift
do {
    let session = try ProtocolSession(
        clientPrivateKey: clientKey,
        serverPublicKey: serverKey
    )
} catch ProtocolSession.Errors.signerCreationFailed {
    print("Client private key invalid for ES256 signing")
} catch ProtocolSession.Errors.serverKeyParseError {
    print("Server public key invalid for ECDH-ES encryption")
} catch ProtocolSession.Errors.clientKeyParseError {
    print("Client key invalid for ECDH-ES decryption")
}
```

### enterSession Errors (Session Mode)

```swift
do {
    try session.enterSession(sessionId: sessionId, sessionKey: sessionKey)
} catch ProtocolSession.Errors.invalidSessionKey {
    print("Session key rejected (wrong size or format)")
} catch ProtocolSession.Errors.failedToCreateDirectDecrypter {
    print("Could not create Direct decrypter from session key")
}
```

## OuterResponse.Error

```swift
enum Error: Swift.Error {
    case invalidSignature            // JWS signature verification failed
    case decodingError(Swift.Error)  // Payload JSON decoding failed
    case unexpectedEncryption(String) // Wrong encryption mode
}
```

### Usage

```swift
do {
    let outerResponse = try OuterResponse(jwsString: serverJWS, session: session)
} catch OuterResponse.Error.invalidSignature {
    print("Server response signature invalid — check server public key")
} catch OuterResponse.Error.decodingError(let underlying) {
    print("Malformed response payload: \(underlying)")
}
```

## OpaqueClientError

```swift
enum OpaqueClientError: Error {
    case clientStartFailure(code: Int32)
    case missingClientStartOutputs
    case clientFinishFailure(code: Int32)
    case missingClientFinishOutputs
    case registrationStartFailure(code: Int32)
    case missingRegistrationStartOutputs
    case registrationFinishFailure(code: Int32)
    case missingRegistrationFinishOutputs
}
```

### Usage

```swift
do {
    let result = try ProtocolRequest.registrationStart(password: password)
} catch let error as OpaqueClientError {
    switch error {
    case .registrationStartFailure(let code):
        print("OPAQUE registration start failed (code \(code))")
    case .missingRegistrationStartOutputs:
        print("OPAQUE produced no output — likely invalid parameters")
    default:
        print("OPAQUE error: \(error)")
    }
    // Recovery: verify password format, restart from beginning
}
```

## PINStretchError

```swift
enum PINStretchError: Error {
    case invalidPasswordEncoding
    case noEnclaveKey
    case invalidEncryptedData
    case decryptionFailed
    case generalError
}
```

### Usage

```swift
let pinStretch = PINStretch()

do {
    let stretched = try pinStretch.stretch(input: pinData)
} catch PINStretchError.noEnclaveKey {
    print("No Secure Enclave key — device may lack SE or key was deleted")
    // AMSecureEnclave auto-generates on init, but may fail on simulator
} catch PINStretchError.invalidPasswordEncoding {
    print("Input data encoding invalid")
} catch PINStretchError.generalError {
    print("PIN stretching failed (e.g., hash-to-curve produced unexpected output)")
}
```

## SignatureVerificationError

```swift
enum SignatureVerificationError: Error {
    case invalidSignature
}
```

### Usage

```swift
do {
    try verifySignature(publicKey: jwkKey, signature: signatureResponse, digest: digest)
} catch SignatureVerificationError.invalidSignature {
    print("ECDSA signature verification failed")
    // Possible causes: wrong key, wrong digest, corrupted signature
}
```

## Common Patterns

### Integration Test Pattern

All integration tests use this error handling pattern (from `testCreateSessionWithRequestObject`):

```swift
do {
    _ = try await client.registration(password: password)
    _ = try await client.authenticate(password: password)
    // ... HSM operations ...
} catch let urlError as URLError {
    switch urlError.code {
    case .cannotConnectToHost, .cannotFindHost,
         .networkConnectionLost, .notConnectedToInternet, .timedOut:
        print("Server not running, skipping")
        return
    default:
        print("Unexpected network error: \(urlError)")
    }
} catch {
    print("Unexpected error: \(error)")
}
```

### Session Expiration Recovery

```swift
do {
    let sig = try await client.sign(hsmKeyId: kid, digest: digest)
} catch let error as BFFHttpClient.APIError {
    if case .httpError(401) = error {
        // Re-authenticate
        _ = try await client.authenticate(password: password)
        // Retry
        let sig = try await client.sign(hsmKeyId: kid, digest: digest)
    }
}
```

## See Also

- ``ProtocolSession/Errors`` — Protocol layer errors
- ``OpaqueClientError`` — OPAQUE client errors
- ``PINStretchError`` — PIN stretching errors
- <doc:Getting-Started> — Error handling in examples
