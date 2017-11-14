import Security
import UIKit
import CryptoSwift

var error: Unmanaged<CFError>?
let dict: [String: Any] = [:]
//Image that will be encrypted by bob, and then decrypted by Alice
let bobImage: UIImage! = UIImage(named:"sf.jpg")
let bobImageData: Data? = UIImageJPEGRepresentation(bobImage, 0.3)
//bobEncryptedImage will represent the chacha20 encrypted value of bob's photo
//If it were a messaging app, this is what would be conveyed to Alice
var bobEncryptedImage: String! = ""
var nonce = "00:00:00:00:00:00:00:00:00:00:00:01"

/*
 Attributes that are to be used in the generation of a secret key for both Bob and Alice. The 3 attributes dicate the key size (32 bytes/256 bits), the key type (eliptic curve), and ephemeral nature
 */
let attributes: [String: Any] = [
    kSecAttrKeySizeInBits as String:      256,
    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: false
    ]
]

/*
 A private key is then generated for both alice and bob, using the SecKeyCreateRandomKey method (https://developer.apple.com/documentation/security/1823694-seckeycreaterandomkey), using the predefined attributes to define the rules behind that key generation
 */
guard let alicePrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    throw error!.takeRetainedValue() as Error
}
guard let bobPrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    throw error!.takeRetainedValue() as Error
}

/*
 Public keys are then generated from the above private keys, using the SecKeyCopyPublicKey method (https://developer.apple.com/documentation/security/1643774-seckeycopypublickey)
 */

let alicePublicKey = SecKeyCopyPublicKey(alicePrivateKey)
let bobPublicKey = SecKeyCopyPublicKey(bobPrivateKey)

/*
 Shared secrets are then created for both alice and bob, using the secKeyExchangeResult method(https://developer.apple.com/documentation/security/1644033-seckeycopykeyexchangeresult?language=objc) that takes in the person's private key, and the recipients public key.
 */
guard let aliceSharedSecret = SecKeyCopyKeyExchangeResult(alicePrivateKey, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256, bobPublicKey!, dict as     CFDictionary, &error) else {
    throw error!.takeRetainedValue() as Error
}
guard let bobSharedSecret = SecKeyCopyKeyExchangeResult(bobPrivateKey, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256, alicePublicKey!, dict as CFDictionary, &error) else {
    throw error!.takeRetainedValue() as Error
}

//ensuring that the shared secrets are the same
guard aliceSharedSecret == bobSharedSecret else {
    throw error!.takeRetainedValue() as Error
}

/*
    -bob's shared key(which is the same as Alice's), is then converted to Data, and turned into a 32bit key using the sha256 method that was imported from the CryptoSwift framework
    -The key is then put into the correct format for the ChaCha20 encryption, where each byte is represented by 2 characters, and the bytes are separated by a colon
 */
let bobSharedSecretData = bobSharedSecret as Data
let aeadKey = bobSharedSecretData.sha256()
let aeadKeyString = aeadKey.map { String(format: "%02hhx", $0) }.joined()
var aeadKeyFormated = ""
let keyChars = Array(aeadKeyString.characters)
stride(from: 0, to: keyChars.count, by: 2).forEach {
    aeadKeyFormated += String(keyChars[$0..<min($0+2, keyChars.count)])
    if $0+2 < keyChars.count {
        aeadKeyFormated += ":"
    }
}

/*
 An AEAD string is created from the AEAD method of ChaCha20-Poly1305, that was implemented for the first project, and is in the Source folder. It is using the key generated from the sha256 hash of the shared secret, and the image date represented in base 64 as its 'plaintext'
 */

let bobImageAEAD:String = AEAD(aeadKeyFormated, nonce, bobImageData!.base64EncodedString(), nil)

let split1 = bobImageAEAD.split(separator:"-")

if let first = split1.first{
    //this is bob's encrypted image, represented as a String
    bobEncryptedImage = String(first)
}

/*---------------------------------------------------------------------
 Alice's perspective, as if she was just sent the encrypted photo
 ---------------------------------------------------------------------*/

//alice generates the sha256 key using her shared secret
let aliceSharedSecretData = aliceSharedSecret as Data
let aliceAeadKey = aliceSharedSecretData.sha256()
let aliceAeadKeyString = aliceAeadKey.map { String(format: "%02hhx", $0) }.joined()
var aliceAeadKeyFormated = ""
let aliceKeyChars = Array(aliceAeadKeyString.characters)
stride(from: 0, to: aliceKeyChars.count, by: 2).forEach {
    aliceAeadKeyFormated += String(aliceKeyChars[$0..<min($0+2, aliceKeyChars.count)])
    if $0+2 < aliceKeyChars.count {
        aliceAeadKeyFormated += ":"
    }
}

//Alice then decrypts bob's secret image, with the key being the sha256 hash value of her shared secret
let aliceDecryptedImageString = chachaDecryption(aliceAeadKeyFormated, nonce, 1, bobEncryptedImage)

//that decrypted string is then converted to data, and opened as an image
let aliceDecryptedImageData:Data = Data(base64Encoded: aliceDecryptedImageString, options: .ignoreUnknownCharacters)!
let aliceDecryptedImage = UIImage(data:aliceDecryptedImageData, scale: 1.0)



