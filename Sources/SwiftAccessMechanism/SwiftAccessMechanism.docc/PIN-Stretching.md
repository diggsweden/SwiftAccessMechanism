# PIN Stretching

Converting weak user PINs to strong cryptographic keys using Secure Enclave.

## Overview

``PINStretch`` converts a weak PIN (e.g., "1234") to a strong 32-byte key via ECDH with a Secure Enclave private key.

## Concept

**Input:** Weak PIN as Data (e.g., "1234".data(using: .utf8)!)
**Output:** 32-byte derived key

**Mechanism:**
1. Hash-to-curve: map PIN bytes to a P-256 point via `hashToCurveP256Sha256`
2. Derive ephemeral private key from the curve point
3. ECDH with Secure Enclave private key (never leaves hardware)
4. HKDF(SHA-256) on ECDH result to produce uniformly distributed 32-byte key

**Security:** Brute-forcing PIN requires device access (Secure Enclave key). Offline attacks infeasible.

## Basic Usage

```swift
import SwiftAccessMechanism

// PINStretch initializes AMSecureEnclave (loads or generates SE key)
let pinStretch = PINStretch()

// Stretch a PIN
let pinData = "1234".data(using: .utf8)!
let stretchedPassword = try pinStretch.stretch(input: pinData)
// stretchedPassword is 32 bytes

// Use with OPAQUE
var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")
_ = try await client.registration(password: stretchedPassword)
_ = try await client.authenticate(password: stretchedPassword)
```

## AMSecureEnclave

``AMSecureEnclave`` manages the Secure Enclave key lifecycle:

### Initialization

On init, ``AMSecureEnclave`` attempts to load an existing SE key. If none found, generates one automatically:

```swift
// Auto-loads or generates SE key
let enclave = AMSecureEnclave()
// enclave.privateKeyRef — SecKey (SE reference)
// enclave.publicKey — Data (public key external representation)
```

### Manual Key Generation

```swift
let enclave = AMSecureEnclave()
try enclave.generateKey()
```

### Key Deletion

```swift
let enclave = AMSecureEnclave()
try await enclave.deleteKey()
// Next AMSecureEnclave init will generate a fresh key
```

### Errors

```swift
enum Errors: Error {
    case keyFetchError    // Failed to load key from Keychain
    case keyDeleteError   // Failed to delete key
    case internalError    // Failed to extract public key
}
```

## Integration with OPAQUE

Stretched PIN serves as OPAQUE password — same PIN always produces same result (deterministic, given same SE key):

```swift
let pinStretch = PINStretch()
let password = try pinStretch.stretch(input: "1234".data(using: .utf8)!)

// Registration (first time)
_ = try await client.registration(password: password)

// Authentication (same PIN → same stretched result → OPAQUE succeeds)
_ = try await client.authenticate(password: password)
```

**Important:** If the Secure Enclave key is deleted and regenerated, stretched values change — user must re-register.

## Security Properties

**Advantages:**
- Weak PIN → strong key (32-byte, uniformly distributed via HKDF)
- Offline attacks infeasible (requires SE access)
- Hardware-backed (SE key never leaves device)
- Device binding (SE key unique per device)

**Limitations:**
- Online attacks still possible (try PINs against live service)
- Mitigation: server-side rate limiting + account lockout

## Implementation Details

### Derivation Steps

1. `hashToCurveP256Sha256(input: pinData, dst: domainTag)` — maps PIN to P-256 point
2. Strip compressed point prefix if present (33 → 32 bytes)
3. Create ephemeral `P256.KeyAgreement.PrivateKey` from raw point
4. `SecKeyCopyKeyExchangeResult(seKey, .ecdhKeyExchangeStandard, ephemeralPubKey)` — ECDH
5. `HKDF<SHA256>.deriveKey(inputKeyMaterial: sharedSecret, salt: ..., info: ...)` — 32-byte output

### Key Storage

Secure Enclave key stored in Keychain:
- Tag: `"se.digg.wallet.app.keys.Test.PINStretch"`
- Key type: `kSecAttrKeyTypeECSECPrimeRandom` (P-256)
- Access: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Flags: `.privateKeyUsage`

## Error Handling

```swift
let pinStretch = PINStretch()

do {
    let stretched = try pinStretch.stretch(input: pinData)
} catch PINStretchError.noEnclaveKey {
    print("No Secure Enclave key available")
    // Simulator or SE initialization failed
} catch PINStretchError.generalError {
    print("Stretching failed — hash-to-curve output unexpected")
} catch {
    print("Unexpected error: \(error)")
}
```

See <doc:Error-Handling> for comprehensive patterns.

## Platform Support

**Requirements:**
- macOS 14+ or iOS 16+
- Device with Secure Enclave (iPhone 5s+, Mac with T2/Apple Silicon)

**Simulators:** Secure Enclave unavailable — ``PINStretch`` will throw ``PINStretchError/noEnclaveKey``.

## See Also

- ``PINStretch`` — PIN stretching API
- ``AMSecureEnclave`` — Secure Enclave key management
- ``PINStretchError`` — Error types
- <doc:Getting-Started> — Integration example
- <doc:Architecture> — Overall design
