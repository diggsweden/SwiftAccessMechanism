//
//  SecureEnclave.swift
//  StatligtElegPrototyp
//
//  Created by Fredrik Thulin on 2024-08-27.
//

import Foundation
import OSLog

public final class MySecureEnclave: ObservableObject {
    fileprivate(set) var publicKey: Data?

    public enum Errors: Error {
        case keyFetchError, keyDeleteError, internalError
    }

    fileprivate let applicationTag = "se.digg.wallet.app.keys.Test.PINStretch"
    //fileprivate(set) var privateKeyRef: SecKey?
    public var privateKeyRef: SecKey?

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
        let _privateKeyRef = item as! SecKey
        guard let _publicKeyRef = SecKeyCopyPublicKey(_privateKeyRef) else {
            Logger.sec.debug("\(#function) Failed copying public key from key reference")
            throw Errors.internalError
        }

        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCopyExternalRepresentation(_publicKeyRef, &error) as? Data else {
            throw error!.takeRetainedValue() as Error
        }

        Logger.sec.debug("\(#function) Loaded Secure Enclave key \(self.applicationTag): \(publicKey.hexString())")

        self.privateKeyRef = _privateKeyRef
        self.publicKey = publicKey
    }

    public func generateKey() throws {
        if self.privateKeyRef != nil {
            Logger.sec.error("\(#function) Key already present: \(self.applicationTag)")
        }

        Logger.sec.debug("\(#function) Generating Secure Enclave key \(self.applicationTag)")

        var error: Unmanaged<CFError>?

        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            //[.privateKeyUsage, .biometryAny],
            &error)

        if error != nil {
            Logger.sec.error("\(#function) FAILED generating access control \(error?.takeRetainedValue())")
            throw error!.takeRetainedValue() as Error
        }

        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: applicationTag,
                kSecAttrAccessControl: access!
            ]
        ]

        guard SecKeyCreateRandomKey(attributes, &error) != nil else {
            Logger.sec.error("\(#function) FAILED generating key \(error?.takeRetainedValue())")
            throw error!.takeRetainedValue() as Error
        }

        do {
            try self.loadKey()
        } catch {
            Logger.sec.error("\(#function) FAILED loading generated key from Secure Enclave: \(error)")
        }
    }

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
