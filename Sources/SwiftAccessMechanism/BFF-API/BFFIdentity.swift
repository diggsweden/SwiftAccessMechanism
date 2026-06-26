// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//
//  BFFIdentity.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2026-02-17.
//

import Foundation
import Security
import OSLog

/// Device identity for BFF protocol: manages two P-256 key pairs and server-assigned client ID.
///
/// On first use, call ``BFFHttpClient/createClient(baseUrl:serverParameters:ttl:)`` to generate
/// Secure Enclave keys and register with the server. Persist the returned identity via
/// ``toClientIdentity()`` and restore it on subsequent launches with ``init(from:)``.
///
/// Modeled after `AMSecureEnclave` — manages only key lifecycle, no HTTP.
public final class BFFIdentity {

    /// Server-assigned client UUID.
    public internal(set) var clientId: String

    /// Keychain `applicationTag` for the SE/Keychain private key.
    public let jwsKeyTag: String

    /// Keychain `applicationTag` for the JWE decryption key.
    public let jweKeyTag: String

    /// DEV-ONLY authorization code returned by `new_state`; required for PIN registration.
    public internal(set) var devAuthorizationCode: String?

    /// P-256 private key (populated by ``init(from:)`` or set directly on creation).
    fileprivate(set) var jwsPrivateKey: SecKey?

    /// JWE decryption private key.
    fileprivate(set) var jwePrivateKey: SecKey?

    /// Errors from Secure Enclave / Keychain operations.
    public enum Errors: Error {
        /// Keychain lookup failed (key not found or access denied).
        case keyFetchError
        /// Keychain delete failed.
        case keyDeleteError
        /// Unexpected internal state (e.g. no private key reference after load).
        case internalError
        /// Failed to extract public key from private key.
        case publicKeyExtractionFailed
        /// String encoding failed (should never happen for UTF-8/ASCII literals).
        case encodingFailed
        /// Keychain item type mismatch.
        case invalidKeychainItem
        /// Key generation failed.
        case keyGenerationFailed
    }

    // MARK: - Init

    /// Restores identity from a persisted ``ClientIdentity``, reloading both keys from Keychain.
    ///
    /// - Parameter identity: Snapshot previously returned by ``toClientIdentity()``.
    /// - Throws: ``Errors/keyFetchError`` if a key is not found in Keychain.
    public init(from identity: ClientIdentity) throws {
        self.clientId = identity.clientId
        self.jwsKeyTag = identity.jwsKeyTag
        self.jweKeyTag = identity.jweKeyTag
        self.devAuthorizationCode = identity.devAuthorizationCode
        try self.loadKeys()
    }

    /// Internal memberwise init — used by `BFFHttpClient` factories.
    init(clientId: String, jwsKeyTag: String, jweKeyTag: String, devAuthorizationCode: String?, jwsPrivateKey: SecKey, jwePrivateKey: SecKey) {
        self.clientId = clientId
        self.jwsKeyTag = jwsKeyTag
        self.jweKeyTag = jweKeyTag
        self.devAuthorizationCode = devAuthorizationCode
        self.jwsPrivateKey = jwsPrivateKey
        self.jwePrivateKey = jwePrivateKey
    }

    /// Pre-registration init — `clientId` and `devAuthorizationCode` are set by ``BFFHttpClient/registerNewDevice(overwrite:ttl:)``.
    init(jwsPrivateKey: SecKey, jwsKeyTag: String, jwePrivateKey: SecKey, jweKeyTag: String) {
        self.clientId = ""
        self.jwsKeyTag = jwsKeyTag
        self.jweKeyTag = jweKeyTag
        self.devAuthorizationCode = nil
        self.jwsPrivateKey = jwsPrivateKey
        self.jwePrivateKey = jwePrivateKey
    }

    // MARK: - Derived properties

    /// JWK thumbprint of the public key as ASCII data — used as OPAQUE client identifier (RFC 7638).
    func opaqueClientId() throws -> Data {
        guard let privateKey = self.jwsPrivateKey else { throw Errors.internalError }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw Errors.publicKeyExtractionFailed
        }
        let thumbprint = try computeJwkThumbprint(publicKey: publicKey)
        guard let thumbprintData = thumbprint.data(using: .ascii) else {
            throw Errors.encodingFailed
        }
        return thumbprintData
    }

    // MARK: - Persistence

    /// Snapshot of this identity for persistence (e.g. `JSONEncoder` → UserDefaults).
    public func toClientIdentity() -> ClientIdentity {
        ClientIdentity(clientId: clientId, jwsKeyTag: jwsKeyTag, jweKeyTag: jweKeyTag, devAuthorizationCode: devAuthorizationCode)
    }

    // MARK: - Key lifecycle

    /// Loads both JWS and JWE private keys from Keychain.
    func loadKeys() throws {
        self.jwsPrivateKey = try Self.loadKeyFromKeychain(tag: jwsKeyTag)
        self.jwePrivateKey = try Self.loadKeyFromKeychain(tag: jweKeyTag)
    }

    private static func loadKeyFromKeychain(tag: String) throws -> SecKey {
        Logger.sec.debug("\(#function) tag=\(tag)")
        guard let tagData = tag.data(using: .utf8) else { throw Errors.encodingFailed }
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tagData,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            Logger.sec.error("\(#function) failed tag=\(tag): \(status)")
            throw Errors.keyFetchError
        }
        guard let key = item, CFGetTypeID(key) == SecKeyGetTypeID() else {
            Logger.sec.error("\(#function) item is not a SecKey tag=\(tag)")
            throw Errors.invalidKeychainItem
        }
        // Force cast is safe: CFGetTypeID verified this is a SecKey
        let secKey = (key as! SecKey)
        Logger.sec.debug("\(#function) loaded tag=\(tag)")
        return secKey
    }

    /// Generates a P-256 private key, stored permanently in the Secure Enclave.
    /// Falls back to a regular Keychain key if SE is unavailable (simulator/Intel Mac).
    ///
    /// - Parameter tag: Keychain `applicationTag` to identify the key.
    /// - Returns: Reference to the generated private key.
    /// - Throws: CFError if key generation fails entirely.
    static func generateKey(tag: String) throws -> SecKey {
        Logger.sec.debug("\(#function) Generating key tag=\(tag)")

        guard let tagData = tag.data(using: .utf8) else {
            throw Errors.encodingFailed
        }
        var error: Unmanaged<CFError>?

        // Try Secure Enclave first
        if let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ), error == nil {
            let attrs: NSDictionary = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs: [
                    kSecAttrIsPermanent: true,
                    kSecAttrApplicationTag: tagData,
                    kSecAttrAccessControl: access
                ]
            ]
            if let key = SecKeyCreateRandomKey(attrs, &error) {
                Logger.sec.debug("\(#function) Generated SE key tag=\(tag)")
                return key
            }
            Logger.sec.debug("\(#function) SE unavailable, falling back: \(error?.takeRetainedValue())")
        }

        // Fallback: regular P-256 Keychain key (e.g. simulator, Intel Mac)
        error = nil
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tagData
            ]
        ]
        guard let key = SecKeyCreateRandomKey(attrs, &error) else {
            if let error = error {
                let cfError = error.takeRetainedValue() as Error
                Logger.sec.error("\(#function) Failed generating fallback key: \(cfError)")
                throw cfError
            }
            throw Errors.keyGenerationFailed
        }
        Logger.sec.debug("\(#function) Generated Keychain (non-SE) key tag=\(tag)")
        return key
    }

    /// Deletes both JWS and JWE private keys from Keychain.
    ///
    /// - Throws: ``Errors/keyDeleteError`` if deletion fails.
    public func deleteKey() throws {
        try Self.deleteKeyFromKeychain(tag: jwsKeyTag)
        try Self.deleteKeyFromKeychain(tag: jweKeyTag)
        self.jwsPrivateKey = nil
        self.jwePrivateKey = nil
    }

    private static func deleteKeyFromKeychain(tag: String) throws {
        Logger.sec.debug("\(#function) tag=\(tag)")
        guard let tagData = tag.data(using: .utf8) else { throw Errors.encodingFailed }
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tagData,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            Logger.sec.error("\(#function) failed tag=\(tag): \(status)")
            throw Errors.keyDeleteError
        }
        Logger.sec.info("\(#function) deleted tag=\(tag)")
    }
}
