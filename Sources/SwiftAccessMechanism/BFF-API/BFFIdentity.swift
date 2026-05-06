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

/// Device identity for BFF protocol: manages a P-256 key pair and server-assigned client ID.
///
/// On first use, call ``BFFHttpClient/createClient(baseUrl:serverParameters:ttl:)`` to generate
/// a Secure Enclave key and register with the server. Persist the returned identity via
/// ``toClientIdentity()`` and restore it on subsequent launches with ``init(from:)``.
///
/// Modeled after `AMSecureEnclave` — manages only key lifecycle, no HTTP.
public final class BFFIdentity {

    /// Server-assigned client UUID.
    public internal(set) var clientId: String

    /// Keychain `applicationTag` for the SE/Keychain private key.
    public let keyTag: String

    /// DEV-ONLY authorization code returned by `new_state`; required for PIN registration.
    public internal(set) var devAuthorizationCode: String?

    /// P-256 private key (populated by ``init(from:)`` or set directly on creation).
    fileprivate(set) var privateKey: SecKey?

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

    /// Restores identity from a persisted ``ClientIdentity``, reloading the private key from Keychain.
    ///
    /// - Parameter identity: Snapshot previously returned by ``toClientIdentity()``.
    /// - Throws: ``Errors/keyFetchError`` if the key is not found in Keychain.
    public init(from identity: ClientIdentity) throws {
        self.clientId = identity.clientId
        self.keyTag = identity.keyTag
        self.devAuthorizationCode = identity.devAuthorizationCode
        try self.loadKey()
    }

    /// Internal memberwise init — used by `BFFHttpClient` factories and `getTestClient`.
    init(clientId: String, keyTag: String, devAuthorizationCode: String?, privateKey: SecKey) {
        self.clientId = clientId
        self.keyTag = keyTag
        self.devAuthorizationCode = devAuthorizationCode
        self.privateKey = privateKey
    }

    /// Pre-registration init — `clientId` and `devAuthorizationCode` are set by ``BFFHttpClient/registerNewDevice(overwrite:ttl:)``.
    init(privateKey: SecKey, keyTag: String) {
        self.clientId = ""
        self.keyTag = keyTag
        self.devAuthorizationCode = nil
        self.privateKey = privateKey
    }

    // MARK: - Derived properties

    /// JWK thumbprint of the public key as ASCII data — used as OPAQUE client identifier (RFC 7638).
    func opaqueClientId() throws -> Data {
        guard let privateKey = self.privateKey else { throw Errors.internalError }
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
        ClientIdentity(clientId: clientId, keyTag: keyTag, devAuthorizationCode: devAuthorizationCode)
    }

    // MARK: - Key lifecycle

    /// Loads the private key from Keychain by `keyTag`.
    func loadKey() throws {
        Logger.sec.debug("\(#function) Loading key tag=\(self.keyTag)")

        guard let tagData = keyTag.data(using: .utf8) else {
            throw Errors.encodingFailed
        }
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tagData,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            Logger.sec.error("\(#function) Failed loading key tag=\(self.keyTag): \(status)")
            throw Errors.keyFetchError
        }

        guard let key = item, CFGetTypeID(key) == SecKeyGetTypeID() else {
            Logger.sec.error("\(#function) Keychain item is not a SecKey")
            throw Errors.invalidKeychainItem
        }
        // Force cast is safe: CFGetTypeID verified this is a SecKey
        self.privateKey = (key as! SecKey)
        Logger.sec.debug("\(#function) Loaded key tag=\(self.keyTag)")
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

    /// Deletes the private key from Keychain.
    ///
    /// - Throws: ``Errors/keyDeleteError`` if deletion fails.
    public func deleteKey() throws {
        Logger.sec.debug("\(#function) Deleting key tag=\(self.keyTag)")

        guard let tagData = keyTag.data(using: .utf8) else {
            throw Errors.encodingFailed
        }
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tagData,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            Logger.sec.error("\(#function) Failed deleting key tag=\(self.keyTag): \(status)")
            throw Errors.keyDeleteError
        }

        self.privateKey = nil
        Logger.sec.info("\(#function) Deleted key tag=\(self.keyTag)")
    }
}
