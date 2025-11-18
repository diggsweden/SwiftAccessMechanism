//
//  DigestAlgorithm.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-08.
//

import Foundation
import CryptoKit

internal protocol DigestAlgorithm {
    func hash(_ data: Data) -> Data
    func digestSize() -> Int
    func inputBlockSize() -> Int
    /// Computes the HMAC (Hash-based Message Authentication Code) for the given data and key.
    ///
    /// - Parameters:
    ///   - key: The key used for the HMAC computation.
    ///   - data: The input data to be authenticated.
    /// - Returns: The computed HMAC as `Data`.
    func hmac(key: Data, data: Data) -> Data
}

internal struct SHA256Algorithm: DigestAlgorithm {
    init() {}

    func hash(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }

    func digestSize() -> Int {
        return SHA256.byteCount
    }

    func inputBlockSize() -> Int {
        return SHA256.blockByteCount * 8
    }

    func hmac(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
    }
}

internal struct SHA384Algorithm: DigestAlgorithm {
    init() {}

    func hash(_ data: Data) -> Data {
        return Data(SHA384.hash(data: data))
    }
    func digestSize() -> Int {
        return SHA384.byteCount
    }

    func inputBlockSize() -> Int {
        return SHA384.blockByteCount * 8
    }

    func hmac(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        return Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
    }
}

internal struct SHA512Algorithm: DigestAlgorithm {
    init() {}

    func hash(_ data: Data) -> Data {
        return Data(SHA512.hash(data: data))
    }
    func digestSize() -> Int {
        return SHA512.byteCount
    }

    func inputBlockSize() -> Int {
        return SHA512.blockByteCount * 8
    }

    func hmac(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
    }
}

internal func hash(_ data: Data, using hashAlgo: DigestAlgorithm) -> Data {
    return hashAlgo.hash(data)
}
