import Foundation
import Testing
@testable import SwiftAccessMechanism
import BigInt

struct TestInputValues {
    let oprfSeed: Data
    let credentialIdentifier: Data
    let password: Data
    let envelopeNonce: Data
    let maskingNonce: Data
    let serverPrivateKey: OpaqueSecretKey
    let serverPublicKey: OpaquePublicKey
    let serverNonce: Data
    let clientNonce: Data
    let clientKeyshareSeed: Data
    let serverKeyshareSeed: Data
    let blindRegistration: String
    let blindLogin: String
}

struct IntermediateValues {
    let clientPublicKey: OpaquePublicKey
    let authKey: Data
    let randomizedPassword: Data
    let envelope: Data
    let handshakeSecret: Data
    let serverMacKey: Data
    let clientMacKey: Data
    let oprfKey: Data
}

struct OutputValues {
    let registrationRequest: String
    let registrationResponse: String
    let registrationUpload: String
    let ke1: String
    let ke2: String
    let ke3: String
    let exportKey: String
    let sessionKey: String
}

struct OpaqueTests {

    @Test func testOpaque3DHRealTestVector5() throws {
//        let oprf = "P256-SHA256"
//        let hash = "SHA256"
//        let ksf = "Identity"
//        let kdf = "HKDF-SHA256"
//        let mac = "HMAC-SHA256"
//        let group = "P256_XMD:SHA-256_SSWU_RO_"
        let context = "OPAQUE-POC".data(using: .ascii)!
//        let nh = 32
//        let npk = 33
//        let nsk = 32
//        let nm = 32
//        let nx = 32
//        let nok = 32

        let inputValues = TestInputValues(
            oprfSeed: Data(hex: "62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2"),
            credentialIdentifier: Data(hex: "31323334"),
            password: Data(hex: "436f7272656374486f72736542617474657279537461706c65"),
            envelopeNonce: Data(hex: "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f"),
            maskingNonce: Data(hex: "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
            serverPrivateKey: OpaqueSecretKey(BInt("c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5", radix: 16)!),
            serverPublicKey: OpaquePublicKey(Data(hex: "035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874").bytes),
            serverNonce: Data(hex: "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1"),
            clientNonce: Data(hex: "ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1"),
            clientKeyshareSeed: Data(hex: "633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc"),
            serverKeyshareSeed: Data(hex: "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f"),
            blindRegistration: "411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153",
            blindLogin: "c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1"
        )

        let intermediateValues = IntermediateValues(
            clientPublicKey: OpaquePublicKey(Data(hex: "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214").bytes),
            authKey: Data(hex: "5bd4be1602516092dc5078f8d699f5721dc1720a49fb80d8e5c16377abd0987b"),
            randomizedPassword: Data(hex: "06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0"),
            envelope: Data(hex: "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8"),
            handshakeSecret: Data(hex: "83a932431a8f25bad042f008efa2b07c6cd0faa8285f335b6363546a9f9b235f"),
            serverMacKey: Data(hex: "13e928581febfad28855e3e7f03306d61bd69489686f621535d44a1365b73b0d"),
            clientMacKey: Data(hex: "afdc53910c25183b08b930e6953c35b3466276736d9de2e9c5efaf150f4082c5"),
            oprfKey: Data(hex: "2dfb5cb9aa1476093be74ca0d43e5b02862a05f5d6972614d7433acdc66f7f31")
        )

        let outputValues = OutputValues(
            registrationRequest: "029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8",
            registrationResponse: "0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874",
            registrationUpload: "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8",
            ke1: "037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6",
            ke2: "0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b",
            ke3: "e97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e",
            exportKey: "c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b",
            sessionKey: "484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1"
        )


        let client = try OpaqueClient(oprfCurve: OprfCurve(profile: .P256_XMD_SHA_256_SSWU_RO), context: context)
        let server = try OpaqueServer(oprfCurve: OprfCurve(profile: .P256_XMD_SHA_256_SSWU_RO), skS: inputValues.serverPrivateKey, context: context)

        //
        // Registration
        //

        /// Test requires deterministic blinding with a scalar supplied in the test vector inputs
        client.setTestingBlindingScalar(BInt(inputValues.blindRegistration, radix: 16)!)

        let (registrationRequest, registrationBlind) = try client.createRegistrationRequest(password: inputValues.password)

        /// Ensure proper serialization of the registration request
        #expect(registrationRequest.data.hexString() == outputValues.registrationRequest)

        let registrationResponse = try server.createRegistrationResponse(request: registrationRequest,
                                                                         credentialIdentifier: inputValues.credentialIdentifier,
                                                                         oprfSeed: inputValues.oprfSeed
        )

        /// Ensure proper computation and serialization of the registration response
        #expect(registrationResponse.serverPublicKey == inputValues.serverPublicKey)
        #expect(registrationResponse.data.hexString() == outputValues.registrationResponse)

        /// Supply a static envelope nonce - the test vector won't match with the standard random one
        client.setTestingNonce(inputValues.envelopeNonce)

        let (registrationRecord, regExportKey) = try client.finalizeRegistrationRequest(password: inputValues.password,
                                                                                        blind: registrationBlind,
                                                                                        response: registrationResponse,
                                                                                        serverIdentity: nil,
                                                                                        clientIdentity: nil,
        )


        /// Ensure proper computation and serialization of the registration record
        #expect(registrationRecord.data.hexString() == outputValues.registrationUpload)
        #expect(regExportKey.hexString() == outputValues.exportKey)

        let clientPublicKey = registrationRecord.clientPublicKey
        #expect(clientPublicKey.data.hexString() == intermediateValues.clientPublicKey.data.hexString())

        //
        // Authentication
        //
        client.setTestingBlindingScalar(BInt(inputValues.blindLogin, radix: 16)!)
        client.setTestingNonce(inputValues.clientNonce)
        client.setTestingKeyshareSeed(inputValues.clientKeyshareSeed)
        let ke1WithState = try client.GenerateKE1(password: inputValues.password)

        #expect(ke1WithState.ke1.data.hexString() == outputValues.ke1)

        server.setTestingNonce(inputValues.serverNonce)
        server.setTestingMaskingNonce(inputValues.maskingNonce)
        server.setTestingKeyshareSeed(inputValues.serverKeyshareSeed)

        let ke2WithState = try server.GenerateKE2(serverIdentity: nil,
                                                  serverPrivateKey: inputValues.serverPrivateKey,
                                                  serverPublicKey: inputValues.serverPublicKey,
                                                  record: registrationRecord,
                                                  credentialIdentifier: inputValues.credentialIdentifier,
                                                  oprfSeed: inputValues.oprfSeed,
                                                  ke1: ke1WithState.ke1,
                                                  clientIdentity: nil)

        #expect(ke2WithState.ke2.data.hexString() == outputValues.ke2)

        let (ke3, sessionKey, authExportKey) = try client.GenerateKE3(ke1WithState: ke1WithState,
                                                                      clientIdentity: nil,
                                                                      serverIdentity: nil,
                                                                      ke2: ke2WithState.ke2,
                                                                      clientPublicKey: clientPublicKey,
                                                                      serverPublicKey: inputValues.serverPublicKey)

        #expect(ke3.data.hexString() == outputValues.ke3)
        #expect(authExportKey.hexString() == outputValues.exportKey)

        let sessionKeyAgain = try server.ServerFinish(ke3: ke3, state: ke2WithState.serverState)
        #expect(sessionKey.hexString() == outputValues.sessionKey)
        #expect(sessionKeyAgain.hexString() == outputValues.sessionKey)
    }
}
