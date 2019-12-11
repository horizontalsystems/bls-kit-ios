import Foundation

public struct Kit {

    public static func verify(messageDigest: Data, pubKey: Data, signature: Data) -> Bool {
        BLSKey.verify(messageDigest, publicKey: pubKey, signature: signature)
    }

}
