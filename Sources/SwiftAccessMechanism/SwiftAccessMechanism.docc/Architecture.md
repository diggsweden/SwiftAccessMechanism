# Architecture

Understanding the protocol stack and design decisions.

## Overview

SwiftAccessMechanism separates protocol layers from cryptographic components:

**Protocol layers:**
```
┌─────────────────────────────────────┐
│ BFF-API (HTTP Client/Layer)        │  Provisional (early development)
├─────────────────────────────────────┤
│ BFF Request/Response DTOs           │  Message format
├─────────────────────────────────────┤
│ Protocol (JWS/JWE Wrapping)         │  ★ STABLE CORE
└─────────────────────────────────────┘
```

**Cryptographic components:**
- PIN Stretching (Secure Enclave ECDH)
- OPAQUE PAKE (Rust FFI)

## Component Details

### PIN Stretching

**Purpose:** Convert weak user PIN (4-6 digits) to strong 32-byte key.

**Approach:** ECDH key exchange with Secure Enclave private key:
- SE private key never leaves hardware
- Ephemeral public key input
- Output: shared secret (32 bytes)

See <doc:PIN-Stretching> for details.

### OPAQUE PAKE

**Purpose:** Password-authenticated key exchange without transmitting password.

**Implementation:** Rust FFI via `OpaqueKeUniffi.xcframework`
- Two-phase registration: start → finish
- Two-phase authentication: start → finish
- Output: `sessionKey` (symmetric) + `sessionId`

**Protocol:** [IRTF CFRG OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)

Minimal wrapper in `OpaqueClient.swift` — implementation details in Rust.

### Protocol Layer (Stable Core)

**Purpose:** JWS/JWE message wrapping for signed + encrypted requests/responses.

**Components:**
- ``ProtocolSession`` — manages signing/encryption state, two modes:
  - **Device mode:** ECDH-ES encryption using server public key (before OPAQUE)
  - **Session mode:** Direct symmetric encryption using OPAQUE session key
- ``OuterRequest``/``OuterResponse`` — JWS signed layer (ES256)
- ``InnerRequest``/``InnerResponse`` — JWE encrypted layer (A256GCM)
- ``ProtocolRequest`` — typed request builders for all operations
- ``ServerParameters`` — server public key + OPAQUE config

**This layer is the stable API.** Can be used directly with custom transport implementation.

See <doc:Protocol-Layer> for detailed API documentation.

### BFF-API (Provisional)

**Purpose:** Provisional HTTP client for early development.

**Components:**
- ``HSMRequest`` — DTO for REST API
- ``BFFLayer`` — builds/parses JWS+JWE messages (transport-independent)
- ``BFFHttpClient`` — HTTP client posting to `/r2ps-api/service`

**Status:** Provisional implementation for project early life. Can be used for prototyping, or replaced with custom transport using the Protocol layer directly.

See <doc:BFF-HTTP-Client> for usage details.

## Crypto Stack

### Outer Layer (JWS Signing)

| Purpose | Algorithm | Key Type | Format |
|---------|-----------|----------|--------|
| Message signing | ES256 | P-256 ECDSA | JWS Compact Serialization |

Client signs all requests with private key. Server verifies signature.

### Inner Layer (JWE Encryption)

**Device Mode** (before OPAQUE authentication):

| Purpose | Algorithm | Key Type | Format |
|---------|-----------|----------|--------|
| Key encryption | ECDH-ES | P-256 ephemeral | JWE Compact Serialization |
| Content encryption | A256GCM | Derived via ECDH | - |

Uses server's public key. Ephemeral key pair created per request.

**Session Mode** (after OPAQUE authentication):

| Purpose | Algorithm | Key Type | Format |
|---------|-----------|----------|--------|
| Key encryption | Direct | Symmetric (32 bytes) | JWE Compact Serialization |
| Content encryption | A256GCM | OPAQUE session key | - |

Direct use of session key from OPAQUE (no key wrapping needed).

### Key Types Summary

- **Client signing key:** P-256 ECDSA (secp256r1)
- **Server public key:** P-256 (for device-mode ECDH-ES)
- **Session key:** 32-byte symmetric (from OPAQUE)
- **HSM keys:** P-256 ECDSA (generated server-side)

All elliptic curve operations use **P-256/secp256r1**.

## Message Flow

### Registration/Authentication (Device Mode)

```
Client                                    Server
  │                                         │
  │  1. Build InnerRequest (plaintext)      │
  │  2. Encrypt → JWE (ECDH-ES)             │
  │  3. Wrap in OuterRequest                │
  │  4. Sign → JWS (ES256)                  │
  │─────────────────────────────────────────>│
  │                                         │
  │  5. Verify JWS signature                │
  │  6. Decrypt JWE (ECDH-ES)               │
  │  7. Process InnerRequest                │
  │  8. Build InnerResponse                 │
  │  9. Encrypt → JWE (ECDH-ES)             │
  │ 10. Wrap in OuterResponse               │
  │<─────────────────────────────────────────│
  │                                         │
  │ 11. Decrypt JWE (ECDH-ES)               │
  │ 12. Parse InnerResponse                 │
```

### HSM Operations (Session Mode)

```
Client                                    Server
  │                                         │
  │  1. Build InnerRequest (plaintext)      │
  │  2. Encrypt → JWE (Direct + sessionKey) │
  │  3. Wrap in OuterRequest (sessionId)    │
  │  4. Sign → JWS (ES256)                  │
  │─────────────────────────────────────────>│
  │                                         │
  │  5. Verify JWS signature                │
  │  6. Decrypt JWE (sessionKey)            │
  │  7. Process InnerRequest                │
  │  8. Build InnerResponse                 │
  │  9. Encrypt → JWE (sessionKey)          │
  │ 10. Wrap in OuterResponse               │
  │<─────────────────────────────────────────│
  │                                         │
  │ 11. Decrypt JWE (sessionKey)            │
  │ 12. Parse InnerResponse                 │
```

## Design Rationale

**Why JWS + JWE?**
- Industry-standard formats (RFC 7515, RFC 7516)
- Mature implementations (JOSESwift)
- Supports both asymmetric (device) and symmetric (session) modes

**Why two encryption modes?**
- **Device mode:** Can make requests before authentication (OPAQUE start)
- **Session mode:** More efficient (no ECDH computation), uses OPAQUE-derived key

**Why separate layers?**
- **Protocol/** is stable and transport-agnostic
- **BFF-API/** can be replaced without touching crypto/OPAQUE
- Clear separation of concerns

## Dependencies

- **JOSESwift** (3.0.0+) — JOSE/JWT/JWE/JWS implementation
- **OpaqueKeUniffi.xcframework** — External binary (Rust OPAQUE client)

No other third-party dependencies.

## Naming Convention

Single-target SPM package — all `.swift` filenames must be unique across directories. BFF-API files use `BFF` prefix to avoid collisions with Protocol/ layer.

## See Also

- <doc:Session-Lifecycle> — Device mode → Session mode transition
- <doc:Protocol-Layer> — Core API reference
- <doc:PIN-Stretching> — PIN stretching design
