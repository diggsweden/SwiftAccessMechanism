//
//  Hash2FieldTests.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-10-14.
//

import Testing
@testable import SwiftAccessMechanism
import Foundation
import BigInt
import SwiftECC

struct Hash2FieldTests {

    struct TestVector {
        let msg: String
        let expectedU0: String
        let expectedU1: String
    }

    func testHash2Field(_ vector: TestVector, h2c: Hash2Curve) throws {
        let scalar = try h2c.hash2Field(vector.msg.data(using: .utf8)!)

        // hash2Field() returns [BInt], u[0] = scalar[0][0], u[1] = scalar[1][0]
        var u0 = scalar[0][0].hexString()
        var u1 = scalar[1][0].hexString()

        // zero-pad u0 and u1 strings if needed
        if u0.count < vector.expectedU0.count {
            u0 = String(repeating: "0", count: vector.expectedU0.count - u0.count) + u0
        }
        if u1.count < vector.expectedU1.count {
            u1 = String(repeating: "0", count: vector.expectedU1.count - u1.count) + u1
        }

        #expect(u0 == vector.expectedU0, "u[0] mismatch for msg '\(vector.msg)'")
        #expect(u1 == vector.expectedU1, "u[1] mismatch for msg '\(vector.msg)'")
    }

    @Test func testWithRFC9380_P256TestVectors() throws {
        // RFC 9380, section J.1.1. P256_XMD:SHA-256_SSWU_RO_

        let dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".data(using: .utf8)!
        let h2c = try Hash2Curve(profile: .P256_XMD_SHA_256_SSWU_RO, domainSeparatorTag: dst)

        let testVectors: [TestVector] = [
            TestVector(
                msg: "",
                expectedU0: "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009",
                expectedU1: "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a"
            ),
            TestVector(
                msg: "abc",
                expectedU0: "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1",
                expectedU1: "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0"
            ),
            TestVector(
                msg: "abcdef0123456789",
                expectedU0: "0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c",
                expectedU1: "b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb"
            )
        ]

        for vector in testVectors {
            try testHash2Field(vector, h2c: h2c)
        }
    }

    @Test func testWithRFC9380_P384TestVectors() throws {
        // RFC 9380, section J.2.1, P384_XMD:SHA-384_SSWU_RO_

        let dst = "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_".data(using: .utf8)!
        let h2c = try Hash2Curve(profile: .P384_XMD_SHA_384_SSWU_RO, domainSeparatorTag: dst)

        let testVectors: [TestVector] = [
            TestVector(
                msg: "",
                expectedU0: "25c8d7dc1acd4ee617766693f7f8829396065d1b447eedb155871feffd9c6653279ac7e5c46edb7010a0e4ff64c9f3b4",
                expectedU1: "59428be4ed69131df59a0c6a8e188d2d4ece3f1b2a3a02602962b47efa4d7905945b1e2cc80b36aa35c99451073521ac"
            ),
            TestVector(
                msg: "abc",
                expectedU0: "53350214cb6bef0b51abb791b1c4209a2b4c16a0c67e1ab1401017fad774cd3b3f9a8bcdf7f6229dd8dd5a075cb149a0",
                expectedU1: "c0473083898f63e03f26f14877a2407bd60c75ad491e7d26cbc6cc5ce815654075ec6b6898c7a41d74ceaf720a10c02e"
            ),
            TestVector(
                msg: "abcdef0123456789",
                expectedU0: "aab7fb87238cf6b2ab56cdcca7e028959bb2ea599d34f68484139dde85ec6548a6e48771d17956421bdb7790598ea52e",
                expectedU1: "26e8d833552d7844d167833ca5a87c35bcfaa5a0d86023479fb28e5cd6075c18b168bf1f5d2a0ea146d057971336d8d1"
            )
        ]

        for vector in testVectors {
            try testHash2Field(vector, h2c: h2c)
        }
    }

    @Test func testWithRFC9380_P521TestVectors() throws {
        // RFC 9380, section J.3.1, P521_XMD:SHA-512_SSWU_RO_

        let dst = "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_".data(using: .utf8)!
        let h2c = try Hash2Curve(profile: .P521_XMD_SHA_512_SSWU_RO, domainSeparatorTag: dst)

        let testVectors: [TestVector] = [
            TestVector(
                msg: "",
                expectedU0: "01e5f09974e5724f25286763f00ce76238c7a6e03dc396600350ee2c4135fb17dc555be99a4a4bae0fd303d4f66d984ed7b6a3ba386093752a855d26d559d69e7e9e",
                expectedU1: "00ae593b42ca2ef93ac488e9e09a5fe5a2f6fb330d18913734ff602f2a761fcaaf5f596e790bcc572c9140ec03f6cccc38f767f1c1975a0b4d70b392d95a0c7278aa"
            ),
            TestVector(
                msg: "abc",
                expectedU0: "003d00c37e95f19f358adeeaa47288ec39998039c3256e13c2a4c00a7cb61a34c8969472960150a27276f2390eb5e53e47ab193351c2d2d9f164a85c6a5696d94fe8",
                expectedU1: "01f3cbd3df3893a45a2f1fecdac4d525eb16f345b03e2820d69bc580f5cbe9cb89196fdf720ef933c4c0361fcfe29940fd0db0a5da6bafb0bee8876b589c41365f15"
            ),
            TestVector(
                msg: "abcdef0123456789",
                expectedU0: "00183ee1a9bbdc37181b09ec336bcaa34095f91ef14b66b1485c166720523dfb81d5c470d44afcb52a87b704dbc5c9bc9d0ef524dec29884a4795f55c1359945baf3",
                expectedU1: "00504064fd137f06c81a7cf0f84aa7e92b6b3d56c2368f0a08f44776aa8930480da1582d01d7f52df31dca35ee0a7876500ece3d8fe0293cd285f790c9881c998d5e"
            )
        ]

        for vector in testVectors {
            try testHash2Field(vector, h2c: h2c)
        }
    }
}

