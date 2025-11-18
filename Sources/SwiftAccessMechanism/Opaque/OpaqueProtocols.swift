import Foundation
import CryptoKit

public protocol KeyDerivationProtocol {
    var extractSize: Int { get }
    var nonceSize: Int { get }
    var seedSize: Int { get }

    func Expand(prk: Data, info: Data, outputLength: Int) -> Data
    func Extract(salt: Data, keyMaterial: Data) -> Data
}
