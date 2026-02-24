# SwiftAccessMechanism

EUDI Wallet credential access library. Protocol stack for OPAQUE PAKE authentication + cloud HSM operations.

## Documentation

**[📖 Full DocC Documentation](Sources/SwiftAccessMechanism/SwiftAccessMechanism.docc/)**

Comprehensive documentation available in DocC format:
- **Getting Started** — complete working examples
- **Architecture** — protocol layers, crypto components, message flow
- **Session Lifecycle** — device mode → session mode transitions
- **Protocol Layer** — stable core API reference
- **Error Handling** — error types and recovery patterns
- **Testing** — test helpers and fixtures

## Quick Overview

### Architecture

**Protocol layers:**
- **Protocol/** — JWS/JWE message wrapping (stable core: `ProtocolSession`, `OuterRequest/Response`, `InnerRequest/Response`)
- **BFF-API/** — Provisional HTTP client (`BFFLayer`, `BFFHttpClient`, message DTOs)

**Cryptographic components:**
- **PINStretch/** — PIN stretching via Secure Enclave ECDH
- **Opaque/** — OPAQUE PAKE client (Rust FFI)

**Note:** BFF-API/ is provisional for early development. Custom transport can be implemented using Protocol/ layer directly.

### Session Flow

1. Stretch PIN via Secure Enclave ECDH
2. Device mode: ECDH-ES encryption with server public key
3. OPAQUE authentication (registration or login)
4. Session mode: Direct symmetric encryption with session key
5. HSM operations: generate/list/sign keys

## Usage

### Quick Start with BFFHttpClient

Based on `testEcdsaSign` integration test:

```swift
import SwiftAccessMechanism
import CryptoKit

var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")
let password = "user-pin".data(using: .utf8)!

// 1. Register (one-time OPAQUE setup)
_ = try await client.registration(password: password)

// 2. Authenticate (establishes session)
let (_, _) = try await client.authenticate(password: password)

// 3. HSM operations
let createdKey = try await client.createHsmKey()
let key = createdKey.public_key

let message = "Hello, EUDI!".data(using: .utf8)!
let digest = Data(SHA256.hash(data: message))
let sig = try await client.sign(hsmKeyId: key.kid, digest: digest)

// 4. Verify signature
try verifySignature(publicKey: key, signature: sig, digest: digest)
```

See [Getting Started](Sources/SwiftAccessMechanism/SwiftAccessMechanism.docc/Getting-Started.md) for complete examples.

## Build & Test

```bash
swift build                    # Build library
swift test                     # Run all tests
swift test --filter testFullRegistrationAuthenticationFlow  # Single test

# Build documentation
xcodebuild docbuild -scheme SwiftAccessMechanism -destination 'generic/platform=macOS'
```

Integration tests require running service at `http://localhost:8088` — skip gracefully if unavailable.

Swift Testing framework (not XCTest), Swift 6.2, platforms macOS 14+/iOS 16+.

## Dependencies

- `JOSESwift` (3.0.0+) — JOSE/JWT/JWE/JWS (SPM dependency)
- `OpaqueKeUniffi.xcframework` — Rust OPAQUE client (external binary)

### Building OpaqueKeUniffi.xcframework

The OPAQUE implementation is a Rust binary that must be built separately:

1. Clone https://github.com/diggsweden/opaque_ke_uniffi/
2. Build xcframework per repository instructions
3. Place built `OpaqueKeUniffi.xcframework` in `external/OpaqueKeUniffi.xcframework/`

Project references the framework at `external/OpaqueKeUniffi.xcframework` in Package.swift.

## Project Structure

```
Sources/SwiftAccessMechanism/
├── SwiftAccessMechanism.docc/    # DocC documentation catalog
├── Protocol/                      # Stable core (JWS/JWE, session mgmt)
├── BFF-API/                       # Provisional HTTP client
├── Opaque/                        # OPAQUE PAKE client
├── PINStretch/                    # PIN stretching + Secure Enclave
└── Common/                        # Utilities
```
