import Foundation
import Testing
@testable import SwiftAccessMechanism

struct SwiftAccessMechanismHighLevelTests {

    @Test func testFullRegistrationLoginFlow() throws {
        let password = Data("test".utf8)

        let (setupHandle, passwordFile, _) = try OpaqueExample.setUp(password: password)

        // Perform login flow using the stored setup handle and password file
        let (clientSessionKey, serverSessionKey) = try OpaqueExample.doLogin(setupHandle: setupHandle, password: password, passwordFile: passwordFile)

        #expect(clientSessionKey == serverSessionKey)
    }
}
