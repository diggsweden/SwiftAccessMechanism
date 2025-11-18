import Foundation
import CryptoKit

public class HKDFKeyDerivation: KeyDerivationProtocol {
    // This class provides the HKDF implementation of the KeyDerivationProtocol

    public let extractSize: Int = 32 // Size of extracted keying material (SHA256 hash size) (aka. Nm)
    public let nonceSize: Int = 32   // Nonce size (Nn) for Opaque
    public let seedSize: Int = 32    // Seed size (Nseed) for Opaque

    public func Expand(prk: Data, info: Data, outputLength: Int) -> Data {
        let symmetricKey = SymmetricKey(data: prk)
        let expandedKey = HKDF<SHA256>.expand(pseudoRandomKey: symmetricKey, info: info, outputByteCount: outputLength)
        return Data(expandedKey.withUnsafeBytes( { $0 }))
    }

    public func Extract(salt: Data, keyMaterial: Data) -> Data {
        let extractedKey = HMAC<SHA256>.authenticationCode(for: keyMaterial, using: SymmetricKey(data: salt))
        return Data(extractedKey)
    }
}
