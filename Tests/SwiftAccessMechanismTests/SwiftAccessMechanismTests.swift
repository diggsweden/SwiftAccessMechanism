//
//  SwiftAccessMechanismTests.swift
//  SwiftAccessMechanismTests
//
//  Created by Fredrik Thulin on 2025-10-03.
//

import Testing
@testable import SwiftAccessMechanism
import SwiftECC
import BigInt
import Foundation

struct SwiftAccessMechanismTests {

    let xValues = [
        "4fe14bb3946e9c23a1cacb43de358e45a9931786067278f6ae3315c216e39a0",
        "d1d12dd2a682259a5dc0da4b79734d4ab6d435c85c8c980e03f8297611e18937",
        "497e89c30c3ed11d291aafcefc02be894f4d87cb29467fa0457b9c02366239d8",
        "d1359226395e08d382cc7528b4ff8ed7f7ed991783fe0eb0f9a3ef2449fb1079",
        "26d12894c6600f99a3ee553a2c339c33058c09f2b7ed184ae9577a0423a9cdf3",
        "5f4edc4e4f1f5dc6eb218bf0791cb80dc264e1d0c2dfcd1cbd00f3b969bcaa56",
        "e87cfbe1079f777ff54c82b3bef8edb4dba40762c4c12715952195bc4c146030",
        "ed1c985837abfb9317126e52849880155a3e70316ac7c4d7ce343024e975b3f5",
        "d7e6c6967d58188bf24bd7aaa04747ab1237725f23eaa47c0e3206f8b4a3c5f5",
        "163f11e2d45d62ed5d4f4503f8fd095a2c292e27554cf859f436332bc3ce6bbe"
    ]

    /// Initialise a SwiftECC domain with the curve P-256 / secp256r1
    /// - Returns: domain instance
    func getDomain() -> Domain {
        return Domain.instance(curve: .EC256r1)
    }

    @Test func testIsSquare() throws {

        let expectedResults = [true, false, false, true, true, false, false, false, true, false]

        let domain = getDomain()
        let order = domain.order
        print("Using curve order: \(order.hexString())")

        for i in 0..<10 {
            let hexString = xValues[i]
            let x = try #require(BInt(hexString, radix: 16), "can't hex decode input value")
            let isSquare = H2cUtils.isSquare(x, order: order)
            print("Integer \(hexString) is square in p256 order: \(isSquare)")
            #expect(expectedResults[i] == isSquare)
        }
    }

    @Test func testSqrt() async throws {
        let expectedResults = [
            "323f7ed2e7c1bd98c010e4f7682e424fd7434feeca6a39ad7f80f3dea00eb18d",
            "1e5f775dc6b369930f58df140498358437461c96cb2857c489c346e3927b6a83",
            "56af41b8f8b6f29f556d1d4471f763a7429d5032fde2156d93d50273858453da",
            "2e1d7226dfcd493860543685107d79a684c11c635cec44b0ed1db566cb3c48d2",
            "92bbc6e0dc62c4f3488cb336c911c75108bddbcd60ad7a2ad7f62f07ecf5ddd8",
            "3f32018e0754b2e744ecd06c9b77e7de171f07e6ad6daf6e914e94108db91073",
            "82353b2f3c9505d15429d6a4d5dd4231c3d116e7300efb39f1deca18164bddf6",
            "3afc13643cc49fb989bd18bde7c2ac2332a99381f3f6081293346e1595fca93d",
            "e4244d900f35a71f23ed02dff6c2bc22f11ca4ebb8dd51e0fcaefd0bd7caeed4",
            "b3ed944452119b21901b25b211c0a5d2f9b40384269c77f488064c9503296bd0"
        ]
        let domain = getDomain()
        print("Using curve \(domain.name) order: \(domain.order.hexString())")
        for i in 0..<expectedResults.count {
            let hexString = xValues[i]
            let x = try #require(BInt(hexString, radix: 16), "can't hex decode input value")
            let sqrt = try #require(H2cUtils.sqrt(x, order: domain.order), "sqrt() failed")
            print("Input #\(i) \(hexString) sqrt in p256 order: \(sqrt.hexString())")
            #expect(sqrt.hexString() == expectedResults[i])
        }
    }

    @Test func testI2Osp() async throws {
        try i2OspTest(4, len: 1, expected: "04")
        try i2OspTest(4, len: 2, expected: "0004")
        try i2OspTest(255, len: 2, expected: "00ff")
        try i2OspTest(256, len: 2, expected: "0100")
        try i2OspTest(1025, len: 2, expected: "0401")
        try i2OspTest(1025, len: 3, expected: "000401")
        #expect(throws: H2cUtils.H2cUtilsError.self) {
            try i2OspTest(1025, len: 1, expected: "000401")
        }
    }

    func i2OspTest(_ inpVal: Int, len: Int, expected: String) throws {
        let i2osp = try H2cUtils.i2osp(inpVal, len: len)
        #expect(i2osp.count == len)
        #expect(i2osp.hexString() == expected)
        let bigInt = H2cUtils.os2ip(i2osp)
        #expect(bigInt == BInt(inpVal))
    }

    @Test func testDigestFunction() throws {
        print("Testing SHA256")
        try digestTest(Data("Hej".utf8), digest: SHA256Algorithm(), len: 32, inpBlockSize: 512, expected: Data(byteEncoded: "20ac4eea95e143bbc7c99b9b927fc49b68c5ff598be50b4929cc0ef3d542b629"))
        print("Testing SHA384")
        try digestTest(Data("Hej".utf8), digest: SHA384Algorithm(), len: 48, inpBlockSize: 1024, expected: Data(byteEncoded: "b1f88d898a7fd16afc24b2127d9c7edc3ed0aa8ce753fd3c8db617728635a2e0c8c700745df359349b899f4a9e514220"))
        print("Testing SHA512")
        try digestTest(Data("Hej".utf8), digest: SHA512Algorithm(), len: 64, inpBlockSize: 1024, expected: Data(byteEncoded: "318bdecec2693e5122f6bd5b635308200406b933ba88f294079aefbd48d856a70341333369a04c10a137793fbf69e72bffa19548c30cc01094255a2ad7a751df"))
    }

    func digestTest(_ data: Data, digest: DigestAlgorithm, len: Int, inpBlockSize: Int, expected: Data?) throws {
        let byteCount = digest.digestSize()
        let blockSize = digest.inputBlockSize()
        let hash = digest.hash(data)

        print("Digest size \(byteCount)")
        print("Internal block size: \(blockSize)")
        print("Digest input: \(hash.hexString())")

        #expect(len == byteCount)
        #expect(inpBlockSize == blockSize)
        #expect(expected == hash)
    }

    @Test func testMessageExpansion() throws {

        let messageExpansion = try XmdMessageExpansion(digestAlgo: SHA256Algorithm(), securityLevelBits: 128)
        let expandedMessage = try messageExpansion.expandMessage("Hej".data(using: .utf8)!, dst: "DST".data(using: .utf8)!, byteLen: 48)

        print("Expanded message: \(expandedMessage.hexString())")

        #expect(expandedMessage.hexString() == "eecb2fbaa0d63c284f61462ab0ee60294486e55b860bf619c9dcb69aa49f72d436bc2a2a862a2f777ab53fc01e4bbeb2")
    }

    @Test func testHashToCurve() throws {
        // These tests use the parameters and input values from the test vectors in RFC9380  J.1.1. P256_XMD:SHA-256_SSWU_RO_
        // but the h2c.hash() function does more computations than the hash-to-field operation, and the expected values are
        // not known from the RFC but rather empirically from this implementation (?).
        let dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".data(using: .utf8)
        let domain = getDomain()
        let ecCurve = SwiftECCurve(domain: Domain.instance(curve: .EC256r1))
        let order = domain.p
        let Z = BInt("ffffffff00000001000000000000000000000000fffffffffffffffffffffff5", radix: 16)
        let L = domain.getCurveLsize(targetSecurityLevelBits: 128)
        #expect(L == Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO.L)
        let m = 1
        let s = 128
        let messageExpansion = try XmdMessageExpansion(digestAlgo: SHA256Algorithm(), securityLevelBits: s)
        let hash2Field = GenericHashToField(dst: dst!, messageExpansion: messageExpansion, L: L, m: m, order: order)
        let map2Curve = SVDWostijneMapToCurve(curve: domain, ecCurve: ecCurve,Z_constant: Z!)
        let h2c = Hash2Curve(curve: domain, ecCurve: ecCurve, hash2Field: hash2Field, map2Curve: map2Curve, messageExpansion: messageExpansion)

        let fieldBits = domain.p.bitWidth
        print("Field size in bits: \(fieldBits)")

        #expect(try hashIndividualMessages("", h2c) == "032c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4")
        #expect(try hashIndividualMessages("abc", h2c) == "020bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f")
        #expect(try hashIndividualMessages("abcdef0123456789", h2c) == "0365038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80")
    }

    func hashIndividualMessages(_ message: String, _ h2c: Hash2Curve) throws -> String {
        let hashPoint = try h2c.hash(message.data(using: .utf8)!)
        print("Hashing message: \(message)")
        print("Hash point: \(hashPoint.hexString())")
        return hashPoint.hexString()
    }


    @Test func testOprfCurves() throws {
        let p256Oprf = try OprfCurve(
            profile: Hash2CurveProfile.P256_XMD_SHA_256_SSWU_RO,
            ecCurve: SwiftECCurve(domain: Domain.instance(curve: .EC256r1))
        )
        print ("Testing P-256")

        try profileH2cIndividualMessages("", p256Oprf,
                                         expectedPoint: "0216623c8d39566ca0503ac2ace1fcd841025cebe0a46295c02cbd2785969a527c",
                                         expectedScalar: "70f54f938502aaa8c66924d26d9c00c2b28686a1eda29b72c4f334a372974c25")
        try profileH2cIndividualMessages("Test", p256Oprf,
                                         expectedPoint: "02da0c1237f4250a5dc5172909cbf26a1f5600114852208a254c5305b1456a9e31",
                                         expectedScalar: "26272571682968ef8f558531f8f22fd5c7284fda0193d72e1140eb28be1c9670")
        try profileH2cIndividualMessages("Domain", p256Oprf, domain: "Domain",
                                         expectedPoint: "0327f337a67a868b1940d352ede30bb0bcd0f1ebdeaeeb0ad2d571bd122c5a011c",
                                         expectedScalar: "e83e763a2a7fd74793ec272a9d2ae4c6020fbf724416f06845617b886b16e4f6")

        let p384Oprf = try OprfCurve(
            profile: Hash2CurveProfile.P384_XMD_SHA_384_SSWU_RO,
            ecCurve: SwiftECCurve(domain: Domain.instance(curve: .EC384r1))
        )
        print ("Testing P-384")

        try profileH2cIndividualMessages("", p384Oprf,
                                         expectedPoint: "02f31cae0beb0de2319c149159b44d686532f68b126bacc3d673cd1c8dcb21b7b2d33691bf85d50e28a414c12ce8b7ac3c",
                                         expectedScalar: "fc18796a859ca482d88171fb466ccd14dc3a8cb5fe4c128690ccbd0616e216528575ed79607a61abe48e70a8fe3cc27a")
        try profileH2cIndividualMessages("Test", p384Oprf,
                                         expectedPoint: "03edec2898b340f16fc0ceeac3938d01bf6315a0a6061a2404ae1a292095e44a4b051f006ae04281cd8777e14a6c715069",
                                         expectedScalar: "40eabbbaccdd9ada54b23831540a0fd520f9cc156e1dafebf7efd66525cff2f59e9de395224220067a9e3474d4cd5f46")
        try profileH2cIndividualMessages("Domain", p384Oprf, domain: "Domain",
                                         expectedPoint: "024ab60906540b6326b69d83b0deb32591c51ad4a7eb949c0eff42aa4d033529b1712fdfa5125ddc789c73956c1cbbf261",
                                         expectedScalar: "8f149d91c2809297c5ccc7d5b24ed3ba39998ca8834c5b3ead45edfadf215f9d4ccad9c50d787fb917e909c33c5ee5e6")
        let p521Oprf = try OprfCurve(
            profile: Hash2CurveProfile.P521_XMD_SHA_512_SSWU_RO,
            ecCurve: SwiftECCurve(domain: Domain.instance(curve: .EC521r1))
        )
        print ("Testing P-521")

        try profileH2cIndividualMessages("", p521Oprf,
                                         expectedPoint: "020145a1fb33dbde9457cd5805b5df6a04ac80f687de418993ea4c19ace25c80dfb23c2e98ec722a8518d4604989ddb2283ff39a390c15362f1726bde5f714ba33cce8",
                                         expectedScalar: "01afffe31c1163ce9f95f53a849de32e8871d42a453c758655d16660c0ff7ed12896f24cd0996f459aa5b6f33770c6d4e7e0351473f7dd954a4c2a38e28c1e52e175")
        try profileH2cIndividualMessages("Test", p521Oprf,
                                         expectedPoint: "0200930eb20883a60154d8f53dfa8480f4230ea01218bbc03160e529e562efd2f18d0b5668ea13a5e5d0f88c9598e0f973f70ad956bd71089dd97753acdb81639b35bc",
                                         expectedScalar: "1a5a4ebd21fc8dfba53d411028dd40e58013528025a2df50577207bc7eadb175aea21e282de04e2647c893e69527209c2135410d7c07cffbf07cc852e0286a07aa")
        try profileH2cIndividualMessages("Domain", p521Oprf, domain: "Domain",
                                         expectedPoint: "030145001dec9a10a93fdd7e12b71da51041b4742ebc8bb4b83dada1512e294f9cb112a3300e9790235788ab459c5627d049fce09829096daf8f289628cbfda47099a0",
                                         expectedScalar: "d93a2a96f2fe958cdeb6c66d4f2cf3af488d4485f2fb7f19c6540462b49d54e2f8e9d81f6523a952915747405abcae648c0a7436746a3fc3b9fdf1f60367a1ae23")
    }

    func profileH2cIndividualMessages(_ message: String, _ h2c: OprfCurve, domain: String = "", expectedPoint: String, expectedScalar: String) throws {
        let hashPoint = try h2c.hash2Curve(message.data(using: .utf8)!)
        print("Hashing message: \(message)")
        print("Hash point: \(hashPoint.hexString())")
        let hashScalar = try h2c.hash2Scalar(message.data(using: .utf8)!, domain: domain)
        print("Hash scalar (domain='\(domain)'): \(hashScalar.hexString())")
        #expect(expectedPoint == hashPoint.hexString())
        #expect(expectedScalar == hashScalar.hexString())
    }
}
