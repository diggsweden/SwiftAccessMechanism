import Foundation
import Testing
@testable import SwiftAccessMechanism

struct SwiftAccessMechanismHighLevelTests {

    @Test func testFullRegistrationAuthenticationFlow() throws {
        let password = Data("test".utf8)

        let (setupHandle, passwordFile, _) = try OpaqueExample.setUp(password: password)

        // Perform authentication flow using the stored setup handle and password file
        let (clientSessionKey, serverSessionKey) = try OpaqueExample.doAuthenticate(setupHandle: setupHandle,
                                                                             password: password,
                                                                             passwordFile: passwordFile)

        #expect(clientSessionKey == serverSessionKey)
    }

    @Test func testPINStretch() throws {
        let pinStretch = PINStretch()

        // Check if Secure Enclave key is available (may fail on simulator/Intel Mac)
        guard pinStretch.privateKeyRef != nil else {
            // Secure Enclave not available - test passes with skip
            return
        }

        let testPIN = Data("1234".utf8)

        // Stretch the PIN using Secure Enclave ECDH
        let stretched = try pinStretch.stretch(input: testPIN)

        // Verify output is 32 bytes
        #expect(stretched.count == 32)

        // Verify deterministic: same input produces same output
        let stretched2 = try pinStretch.stretch(input: testPIN)
        #expect(stretched == stretched2)

        // Verify different inputs produce different outputs
        let differentPIN = Data("5678".utf8)
        let stretchedDifferent = try pinStretch.stretch(input: differentPIN)
        #expect(stretched != stretchedDifferent)
        #expect(stretchedDifferent.count == 32)
    }
}
