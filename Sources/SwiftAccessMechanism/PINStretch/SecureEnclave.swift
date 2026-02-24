//
//  SecureEnclave.swift
//  StatligtElegPrototyp
//
//  Created by Fredrik Thulin on 2024-08-27.
//

import Foundation
import OSLog

/// Manages a P-256 private key in the device's Secure Enclave for PIN stretching.
///
/// On init, attempts to load an existing key from the Keychain. If none exists, generates a new one.
/// Used by ``PINStretch`` for ECDH key agreement.
public final class AMSecureEnclave: ObservableObject {
    /// X9.63 representation of the public key, or `nil` if key not loaded.
    fileprivate(set) var publicKey: Data?

    /// Errors from Secure Enclave key operations.
    public enum Errors: Error {
        /// Failed to load key from Keychain.
        case keyFetchError
        /// Failed to delete key from Keychain.
        case keyDeleteError
        /// Internal error (e.g. could not extract public key).
        case internalError
        /// Keychain item type mismatch.
        case invalidKeychainItem
        /// Failed to create access control or generate key.
        case keyGenerationFailed
    }

    fileprivate let applicationTag = "se.digg.wallet.app.keys.Test.PINStretch"
    /// Reference to the Secure Enclave private key, or `nil` if unavailable.
    public var privateKeyRef: SecKey?

    /// Loads existing Secure Enclave key, or generates a new one if none found.
    public init() {
        do {
            try self.loadKey()
        } catch {
            Logger.sec.error("\(#function) FAILED loading key from Secure Enclave: \(error)")
            do {
                try self.generateKey()
            } catch {
                Logger.sec.error("\(#function) FAILED generating key in Secure Enclave: \(error)")
            }
        }
    }

    internal func loadKey() throws {
        Logger.sec.debug("\(#function) Loading Secure Enclave key \(self.applicationTag)")

        let query: NSDictionary = [kSecClass: kSecClassKey,
                      kSecAttrApplicationTag: applicationTag,
                             kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                               kSecReturnRef: true]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { throw Errors.keyFetchError }
        guard let key = item, CFGetTypeID(key) == SecKeyGetTypeID() else {
            Logger.sec.error("\(#function) Keychain item is not a SecKey")
            throw Errors.invalidKeychainItem
        }
        // Force cast is safe: CFGetTypeID verified this is a SecKey
        let _privateKeyRef = (key as! SecKey)
        guard let _publicKeyRef = SecKeyCopyPublicKey(_privateKeyRef) else {
            Logger.sec.debug("\(#function) Failed copying public key from key reference")
            throw Errors.internalError
        }

        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCopyExternalRepresentation(_publicKeyRef, &error) as? Data else {
            if let error = error {
                let cfError = error.takeRetainedValue() as Error
                throw cfError
            }
            throw Errors.internalError
        }

        Logger.sec.debug("\(#function) Loaded Secure Enclave key \(self.applicationTag): \(publicKey.hexString())")

        self.privateKeyRef = _privateKeyRef
        self.publicKey = publicKey
    }

    /// Generates a new P-256 key in the Secure Enclave and loads it.
    public func generateKey() throws {
        if self.privateKeyRef != nil {
            Logger.sec.error("\(#function) Key already present: \(self.applicationTag)")
        }

        Logger.sec.debug("\(#function) Generating Secure Enclave key \(self.applicationTag)")

        var error: Unmanaged<CFError>?

        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            //[.privateKeyUsage, .biometryAny],
            &error) else {
            if let error = error {
                let cfError = error.takeRetainedValue() as Error
                Logger.sec.error("\(#function) FAILED generating access control \(cfError)")
                throw cfError
            }
            throw Errors.keyGenerationFailed
        }

        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: applicationTag,
                kSecAttrAccessControl: access
            ]
        ]

        guard SecKeyCreateRandomKey(attributes, &error) != nil else {
            if let error = error {
                let cfError = error.takeRetainedValue() as Error
                Logger.sec.error("\(#function) FAILED generating key \(cfError)")
                throw cfError
            }
            throw Errors.keyGenerationFailed
        }

        do {
            try self.loadKey()
        } catch {
            Logger.sec.error("\(#function) FAILED loading generated key from Secure Enclave: \(error)")
        }
    }

    /// Deletes the Secure Enclave key from the Keychain.
    public func deleteKey() async throws {
        Logger.sec.debug("\(#function) Deleting Secure Enclave key \(self.applicationTag)")

        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: applicationTag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            Logger.sec.error("\(#function) FAILED deleted Secure Enclave key \(self.applicationTag): \(status)")
            throw Errors.keyDeleteError }

        Logger.sec.info("\(#function) Deleted Secure Enclave key \(self.applicationTag)")
    }

}
