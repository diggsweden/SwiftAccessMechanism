//
//  OprfCurveTests.swift
//  SwiftAccessMechanismTests
//
//  Created by Fredrik Thulin on 2025-10-08.
//

import Testing
@testable import SwiftAccessMechanism
import Foundation
import BigInt
import SwiftECC

struct OprfCurveTests {

    @Test func testP256() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO)
        let scalar = try oprfCurve.hash2Scalar("Test".data(using: .utf8)!)
        let curve = oprfCurve.profile.curve
        let g = curve.g
        let multiply = try curve.multiplyPoint(g, scalar)
        let addPoint = try curve.addPoints(g, multiply)

        print("Scalar        :\(scalar.hexString())")
        print("Generator     :\(g.hexString(curve))")
        print("Multiply (com):\(multiply.hexString(curve))")
        print("Add:          :\(addPoint.hexString(curve))")

        #expect("26272571682968ef8f558531f8f22fd5c7284fda0193d72e1140eb28be1c9670" == scalar.hexString())
        #expect("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" == g.hexString(curve))
        #expect("04e182dc95f4db72012dc7139bd069baeab86f07e11887fe75f6c4628fc6246fc851b6c5713147bcea6656c61e4ed3685385f11d39c5258b7028049c9cd30ba266" == multiply.hexString(curve, false))
        #expect("02e182dc95f4db72012dc7139bd069baeab86f07e11887fe75f6c4628fc6246fc8" == multiply.hexString(curve))
        #expect("02d6b9d822fbe6b47a9f5d0d516df51e1af1a60660fbfd9274b263c9aca5821777" == addPoint.hexString(curve))

        let curveOrder = curve.order
        print("Curve order \(curveOrder.hexString())")
        print("Field order \(curve.p.hexString())")
        print("Field A \(curve.a.hexString())")
        print("Field B \(curve.b.hexString())")

        let L = curve.getCurveLsize(targetSecurityLevelBits: 128)
        print("Curve L size with security level 128: \(L)")

        let bitsize = curve.p.bitWidth
        print("Curve bitsize: \(bitsize)")

        let cofactor = curve.cofactor
        print("Cofactor: \(cofactor)")

    }

    @Test func testP521() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P521_XMD_SHA_512_SSWU_RO)
        let scalar = try oprfCurve.hash2Scalar("Test".data(using: .utf8)!)
        let curve = oprfCurve.profile.curve
        let g = curve.g
        let multiply = try curve.multiplyPoint(g, scalar)
        let addPoint = try curve.addPoints(g, multiply)

        print("Scalar        :\(scalar.hexString())")
        print("Generator     :\(g.hexString(curve))")
        print("Multiply (raw):\(multiply.hexString(curve, false))")
        print("Multiply (com):\(multiply.hexString(curve))")
        print("Add:          :\(addPoint.hexString(curve))")

        #expect("1a5a4ebd21fc8dfba53d411028dd40e58013528025a2df50577207bc7eadb175aea21e282de04e2647c893e69527209c2135410d7c07cffbf07cc852e0286a07aa" == scalar.hexString())
        #expect("0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66" == g.hexString(curve))
        #expect("04019147770453b56ab314fe36ca292001822f9033cf2167d15178637bcc059fe0febf3fb5731e7675b6b488ce9d24229eb09bfcf2dc714cb564ab59f79e4e462b33490095c0522f3aa6c8b86b9976731ec18f5d5560a3464bc306eef03e4eb5192bf98c00aa4ac32adc50595a4f65f74e094c8d71b4d7f95011a24b655c93c0da282c078e" == multiply.hexString(curve, false))
        #expect("02019147770453b56ab314fe36ca292001822f9033cf2167d15178637bcc059fe0febf3fb5731e7675b6b488ce9d24229eb09bfcf2dc714cb564ab59f79e4e462b3349" == multiply.hexString(curve))
        #expect("0301655d3f9433835a707ae695fd499ee4b8d6f21fabfac4a2749eecfb75b1fec457be7819055328516627853e7a12410f05191e67fe57e678b7d8d7984dab0f31b06a" == addPoint.hexString(curve))
    }

    // Struct to hold a test vector from RFC9497, Appendix A
    struct TestVector {
        let input: Data
        let blindHex: String
        let expectedBlindedElement: String
        let skSm: BInt
        let expectedEvaluatedElement: String
        let expectedOutput: String
    }

    @Test func testBlindWithVectors_P256() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO)

        // Vectors from RFC9497, A.3.  P256-SHA256 - OPRF Mode
        let testVectors = [
            TestVector(
                input: Data([0x00]),
                blindHex: "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
                expectedBlindedElement: "03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d",
                skSm: BInt("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf", radix: 16)!,
                expectedEvaluatedElement: "030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832",
                expectedOutput: "a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd"
            ),
            TestVector(
                input: Data([0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a]),
                blindHex: "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
                expectedBlindedElement: "03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838",
                skSm: BInt("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf", radix: 16)!,
                expectedEvaluatedElement: "03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c",
                expectedOutput: "c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce"
            )
        ]
        for vector in testVectors {
            try runOprf(vector: vector, oprfCurve: oprfCurve)
        }
    }

    @Test func testBlindWithVectors_P384() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P384_XMD_SHA_384_SSWU_RO)

        // Vectors from RFC9497, A.4.  P384-SHA256 - OPRF Mode
        let testVectors = [
            TestVector(
                input: Data([0x00]),
                blindHex: "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
                expectedBlindedElement: "02a36bc90e6db34096346eaf8b7bc40ee1113582155ad3797003ce614c835a874343701d3f2debbd80d97cbe45de6e5f1f",
                skSm: BInt("dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188", radix: 16)!,
                expectedEvaluatedElement: "03af2a4fc94770d7a7bf3187ca9cc4faf3732049eded2442ee50fbddda58b70ae2999366f72498cdbc43e6f2fc184afe30",
                expectedOutput: "ed84ad3f31a552f0456e58935fcc0a3039db42e7f356dcb32aa6d487b6b815a07d5813641fb1398c03ddab5763874357"
            ),
            TestVector(
                input: Data([0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a]),
                blindHex: "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
                expectedBlindedElement: "02def6f418e3484f67a124a2ce1bfb19de7a4af568ede6a1ebb2733882510ddd43d05f2b1ab5187936a55e50a847a8b900",
                skSm: BInt("dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188", radix: 16)!,
                expectedEvaluatedElement: "034e9b9a2960b536f2ef47d8608b21597ba400d5abfa1825fd21c36b75f927f396bf3716c96129d1fa4a77fa1d479c8d7b",
                expectedOutput: "dd4f29da869ab9355d60617b60da0991e22aaab243a3460601e48b075859d1c526d36597326f1b985778f781a1682e75"
            )
        ]
        for vector in testVectors {
            try runOprf(vector: vector, oprfCurve: oprfCurve)
        }
    }

    @Test func testBlindWithVectors_P521() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P521_XMD_SHA_512_SSWU_RO)

        // Vectors from RFC9497, A.5.  P521-SHA256 - OPRF Mode
        let testVectors = [
            TestVector(
                input: Data([0x00]),
                blindHex: "00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
                expectedBlindedElement: "0300e78bf846b0e1e1a3c320e353d758583cd876df56100a3a1e62bacba470fa6e0991be1be80b721c50c5fd0c672ba764457acc18c6200704e9294fbf28859d916351",
                skSm: BInt("0153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6", radix: 16)!,
                expectedEvaluatedElement: "030166371cf827cb2fb9b581f97907121a16e2dc5d8b10ce9f0ede7f7d76a0d047657735e8ad07bcda824907b3e5479bd72cdef6b839b967ba5c58b118b84d26f2ba07",
                expectedOutput: "26232de6fff83f812adadadb6cc05d7bbeee5dca043dbb16b03488abb9981d0a1ef4351fad52dbd7e759649af393348f7b9717566c19a6b8856284d69375c809"
            ),
            TestVector(
                input: Data([0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a]),
                blindHex: "00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
                expectedBlindedElement: "0300c28e57e74361d87e0c1874e5f7cc1cc796d61f9cad50427cf54655cdb455613368d42b27f94bf66f59f53c816db3e95e68e1b113443d66a99b3693bab88afb556b",
                skSm: BInt("0153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6", radix: 16)!,
                expectedEvaluatedElement: "0301ad453607e12d0cc11a3359332a40c3a254eaa1afc64296528d55bed07ba322e72e22cf3bcb50570fd913cb54f7f09c17aff8787af75f6a7faf5640cbb2d9620a6e",
                expectedOutput: "ad1f76ef939042175e007738906ac0336bbd1d51e287ebaa66901abdd324ea3ffa40bfc5a68e7939c2845e0fd37a5a6e76dadb9907c6cc8579629757fd4d04ba"
            )
        ]
        for vector in testVectors {
            try runOprf(vector: vector, oprfCurve: oprfCurve)
        }
    }

    @Test func testDeserializeInfinity() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO)
        let infinityData = Data([0x00])
        let infinityBytes: [UInt8] = [0x00]

        #expect(throws: OprfCurve.OprfCurveError.invalidInputError) {
            try oprfCurve.deserializeElement(infinityData)
        }

        #expect(throws: OprfCurve.OprfCurveError.invalidInputError) {
            try oprfCurve.deserializeElement(infinityBytes)
        }
    }

    @Test func testSerializeDeserializeRoundtrip() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO)
        let curve = oprfCurve.profile.curve
        let g = curve.g

        let encoded = try oprfCurve.serializeElement(g)
        let dataEncoded = Data(encoded)

        let decodedFromBytes = try oprfCurve.deserializeElement(encoded)
        let decodedFromData = try oprfCurve.deserializeElement(dataEncoded)

        // The decoded points should equal the original point
        #expect(decodedFromBytes == g)
        #expect(decodedFromData == g)
    }

    @Test func testDeserializeInvalidBytes() throws {
        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO)

        // Take a valid point and change one byte to make it invalid
        let encoded = try oprfCurve.serializeElement(oprfCurve.profile.curve.g)
        var badEncoded = encoded
        // decrement last byte (wrapping) to make the encoding invalid
        badEncoded[badEncoded.count - 1] = badEncoded[badEncoded.count - 1] &- 1

        #expect(throws: ECException.decodePoint) {
            try oprfCurve.deserializeElement(badEncoded)
        }

        #expect(throws: ECException.decodePoint) {
            try oprfCurve.deserializeElement(Data(badEncoded))
        }
    }

    @Test func testDeserializePointFromOtherCurve() throws {
        // Create a P384 point and try to decode it with a P256 OPRF curve
        let otherOprf = try OprfCurve(profile: Hash2CurveProfile.P384_XMD_SHA_384_SSWU_RO)
        let otherEncoded = try otherOprf.serializeElement(otherOprf.profile.curve.g)

        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO)
        let encoded = try oprfCurve.serializeElement(oprfCurve.profile.curve.g)

        // Decoding P384-encoded point with P256 domain should fail (decode error)
        #expect(throws: ECException.decodePoint) {
            try oprfCurve.deserializeElement(otherEncoded)
        }

        #expect(try oprfCurve.deserializeElement(encoded) == oprfCurve.profile.curve.g)
    }

    @Test func testDeriveKeyPair() throws {
        // Test with key from RFC9497, A.3. P256-SHA256 - OPRF Mode
        let seed = Data(repeating: 0xa3, count: 32)
        let keyInfo = Data("test key".utf8)
        let expectedSkSmHex = "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf"

        let oprfCurve = try OprfCurve(profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO)

        let (skSm, _) = try oprfCurve.deriveKeyPair(seed: seed, info: keyInfo)

        // Assert the derived scalar matches the expected value
        #expect(skSm.hexString() == expectedSkSmHex, "Derived scalar skSm does not match the expected value.")
    }

    /// This is a test implementation of the "OPRF Protocol" described in RFC9497,  3.3.1. OPRF Protocol
    /// - Parameters:
    ///   - vector: Test vector with inputs and expected outputs
    ///   - oprfCurve: The OPRF curve to use
    func runOprf(vector: TestVector, oprfCurve: OprfCurve) throws {
        // perform the first step on the client
        let blindingScalar = BInt(vector.blindHex, radix: 16)!
        let (blind, blindedElement) = try oprfCurve.blind(input: vector.input, testingScalar: blindingScalar)
        #expect(blind == blindingScalar) // verify no random blind was generated when calling the deterministic Blind()
        #expect(Data(blindedElement).hexString() == vector.expectedBlindedElement)

        // perform the part that would be done on the server
        let evaluatedElement = try oprfCurve.blindEvaluate(skS: vector.skSm, blindedElement: blindedElement)
        #expect(Data(evaluatedElement).hexString() == vector.expectedEvaluatedElement)

        // perform the last step on the client again
        let output = try oprfCurve.finalize(input: vector.input, blind: blind, evaluatedElement: evaluatedElement)
        #expect(output.hexString() == vector.expectedOutput)
    }
}
