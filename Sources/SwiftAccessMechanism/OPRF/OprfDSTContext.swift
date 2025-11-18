//
//  OprfDSTContext.swift
//  ECOps
//
//  Created by Stefan Santesson on 2024-07-09.
//

import Foundation


/// Domain Separation Tag for use in OPRF, see [RFC9497], Section 4 / [RFC9380], Section 3.1
internal class OprfDSTContext {
    enum OprfDstError: Error {
        case invalidInput
    }

    private static let VERSION_OPRFV1 = "OPRFV1"
    static let IDENTIFIER_P256_SHA256 = "P256-SHA256"
    fileprivate static let IDENTIFIER_DECAF448_SHAKE256 = "decaf448-SHAKE256"  // not implemented
    static let IDENTIFIER_P384_SHA384 = "P384-SHA384"
    static let IDENTIFIER_P521_SHA512 = "P521-SHA512"
    private static let MODE_OPRF = 0
    private static let MODE_VOPRF = 1
    private static let MODE_POPRF = 2

    fileprivate let version: String
    fileprivate let mode: Int
    fileprivate let identifier: String

    let contextString: Data

    init(version: String, mode: Int, identifier: String) throws {
        self.version = version
        self.mode = mode
        self.identifier = identifier

        self.contextString = try OprfDSTContext.concat(version, "-", mode, "-", identifier)
    }

    convenience init(mode: Int, identifier: String) throws {
        try self.init(version: OprfDSTContext.VERSION_OPRFV1, mode: mode, identifier: identifier)
    }

    convenience init(identifier: String) throws {
        try self.init(version: OprfDSTContext.VERSION_OPRFV1, mode: OprfDSTContext.MODE_OPRF, identifier: identifier)
    }

    func getHash2CurveDST() -> Data? {
        return getDomainSeparationTag("HashToGroup-")
    }

    func getHash2ScalarDefaultDST() -> Data? {
        return getDomainSeparationTag("HashToScalar-")
    }

    func getDomainSeparationTag(_ domain: String) -> Data? {
        return try? OprfDSTContext.concat(domain, self.contextString)
    }

    /// Concatenate components of types String, Int and Data into a Data result
    ///
    /// NOTE: Integers are converted to a single byte (1 byte length)
    ///
    /// - Parameter components: Input components of type String, Int or Data
    /// - Returns: Concatenated components as Data
    fileprivate static func concat(_ components: Any...) throws -> Data {
        var result = Data()
        for component in components {
            if let str = component as? String {
                if let data = str.data(using: .utf8) {
                    result.append(data)
                } else {
                    throw OprfDstError.invalidInput
                }
            } else if let intVal = component as? Int {
                result.append(try H2cUtils.i2osp(intVal, len: 1))
            } else if let data = component as? Data {
                result.append(data)
            } else {
                throw OprfDstError.invalidInput
            }
        }
        return result
    }

}
