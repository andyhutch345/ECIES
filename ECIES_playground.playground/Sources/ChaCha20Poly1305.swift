/*
 Code written by Andy Hutchison, modeled after the implementation of ChaCha20-Poly1305 defined at https://tools.ietf.org/html/rfc7539
 */

import UIKit
import Foundation

public var key: String = ""
public var nonce: String = ""
public var count: Int = 0
public var plaintext: String = ""
public var ciphertext: String = ""
public var decipheredtext: String = ""
public var aad: String = ""
public var aead: String = ""
public var block: String = ""
public var tag: String = ""

public func leftRotation(for intArg: UInt32, by shift: Int) -> UInt32 {
    return ((intArg << shift) | (intArg >> (32-shift)))
}

public func chacha_quarter(onState chachaState: [[UInt32]], _ x:Int, _ y:Int, _ z:Int, _ w:Int) -> [[UInt32]]{
    var a64:UInt?
    var c64:UInt?
    
    var a: UInt32 = chachaState[x/4][x%4]
    var b: UInt32 = chachaState[y/4][y%4]
    var c: UInt32 = chachaState[z/4][z%4]
    var d: UInt32 = chachaState[w/4][w%4]
    
    var chachaState = chachaState
    
    //1
    a64 = UInt(UInt(a)+UInt(b))
    a = UInt32(truncatingIfNeeded: a64!)
    d = d^a
    d = leftRotation(for: d, by: 16)
    
    //2
    c64 = UInt(UInt(c)+UInt(d))
    c = UInt32(truncatingIfNeeded:c64!)
    b = b^c
    b = leftRotation(for: b, by: 12)
    
    //3
    a64 = UInt(UInt(a)+UInt(b))
    a = UInt32(truncatingIfNeeded: a64!)
    d = d^a
    d = leftRotation(for: d, by: 8)
    
    //4
    c64 = UInt(UInt(c)+UInt(d))
    c = UInt32(truncatingIfNeeded:c64!)
    b = b^c
    b = leftRotation(for: b, by: 7)
    
    chachaState[x/4][x%4] = a
    chachaState[y/4][y%4] = b
    chachaState[z/4][z%4] = c
    chachaState[w/4][w%4] = d
    
    return chachaState
}

public func chacha20_block(_ key: String, _ nonce: String, _ count: Int) -> String {
    var chacha_state: [[UInt32]] = [
        [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
        [0,0,0,0],
        [0,0,0,0],
        [0,0,0,0]]
    var keystreamString: String = ""
    let keyOctets = key.split(separator: ":")
    let nonceOctets = nonce.split(separator: ":")
    for x in 0...7{
        var wordValue: String = ""
        for i in 0...3{
            let index = (x*4) + i
            wordValue = keyOctets[index] + wordValue
        }
        let wordInt = UInt32(wordValue, radix: 16)!
        let stateIndex = x+4
        chacha_state[stateIndex/4][stateIndex%4] = wordInt
    }
    
    chacha_state[3][0] = UInt32(count)
    
    for a in 0...2{
        var wordValue: String = ""
        for b in 0...3{
            let index = (a*4) + b
            wordValue = nonceOctets[index] + wordValue
        }
        let wordInt = UInt32(wordValue, radix: 16)!
        let stateIndex = a+13
        chacha_state[stateIndex/4][stateIndex%4] = wordInt
    }
    
    let chachaOriginal = chacha_state
    var chacha_hex: [[String]] = [["","","",""],["","","",""],["","","",""],["","","",""]]
    
    for index in 0...19{
        if index%2 == 0{
            chacha_state = chacha_quarter(onState: chacha_state, 0, 4, 8, 12)
            chacha_state = chacha_quarter(onState: chacha_state, 1, 5, 9, 13)
            chacha_state = chacha_quarter(onState: chacha_state, 2, 6, 10, 14)
            chacha_state = chacha_quarter(onState: chacha_state, 3, 7, 11, 15)
        }else {
            chacha_state = chacha_quarter(onState: chacha_state, 0, 5, 10, 15)
            chacha_state = chacha_quarter(onState: chacha_state, 1, 6, 11, 12)
            chacha_state = chacha_quarter(onState: chacha_state, 2, 7, 8, 13)
            chacha_state = chacha_quarter(onState: chacha_state, 3, 4, 9, 14)
        }
    }
    
    for i in 0...15{
        let carrylessAddition:UInt = UInt(chachaOriginal[i/4][i%4]) + UInt(chacha_state[i/4][i%4])
        chacha_state[i/4][i%4] = UInt32(truncatingIfNeeded:carrylessAddition)
        chacha_hex[i/4][i%4] = String(chacha_state[i/4][i%4], radix:16)
    }
    
    for r in 0...3{
        for s in 0...3{
            var hexValue = chacha_hex[r][s]
            while hexValue.count < 8{
                hexValue = "0" + hexValue
            }
            var substream = ""
            for t in 0...3{
                let start = hexValue.index(hexValue.startIndex, offsetBy: t*2)
                let end = hexValue.index(hexValue.startIndex, offsetBy: (t*2)+2)
                let range = start..<end
                let digitHex = hexValue.substring(with:range)
                if r==3 && s==3 && t==0{
                    substream = digitHex
                } else {
                    substream = digitHex + ":" + substream
                }
            }
            keystreamString += substream
        }
    }
    
    return keystreamString
}

public func chachaEncryption(_ key: String, _ nonce: String, _ count: Int, _ plaintext: String) -> String{
    var encryptedMessage = ""
    var keyStream:String
    var hexedText = ""
    for character in plaintext.characters{
        let char = String(character).unicodeScalars
        if hexedText == ""{
            hexedText += String(char[char.startIndex].value, radix:16)
        } else {
            hexedText += ":" + String(char[char.startIndex].value, radix:16)
        }
    }
    if ((plaintext.count/64) > 0) {
        for j in 0...(plaintext.count/64)-1{
            keyStream = chacha20_block(key, nonce, count+j)
            let start = hexedText.index(hexedText.startIndex, offsetBy: 64*3*j)
            let end = hexedText.index(hexedText.startIndex, offsetBy: (64*3*j)+(64*3-1))
            let range = start..<end
            let block = hexedText.substring(with:range)
            let keyStreamArray = keyStream.split(separator: ":")
            let plaintextArray = block.split(separator: ":")
            for t in 0...keyStreamArray.count-1{
                let keyValue = UInt32(keyStreamArray[t], radix: 16)!
                let textValue = UInt32(plaintextArray[t], radix: 16)!
                let xOrEd = keyValue ^ textValue
                if (String(xOrEd, radix:16).count == 1){
                    if encryptedMessage == ""{
                        encryptedMessage += "0" + String(xOrEd, radix:16)
                    }else {
                        encryptedMessage += ":0" + String(xOrEd, radix:16)
                    }
                }else{
                    if encryptedMessage == ""{
                        encryptedMessage += String(xOrEd, radix:16)
                        
                    } else {
                        encryptedMessage += ":" + String(xOrEd, radix:16)
                        
                    }
                }
            }
        }
    }
    if (plaintext.count % 64) != 0{
        let index = plaintext.count/64
        keyStream = chacha20_block(key, nonce, count+index)
        let start = hexedText.index(hexedText.startIndex, offsetBy: (64*3*index))
        let block = hexedText.substring(from:start)
        let keyStreamArray = keyStream.split(separator: ":")
        let plaintextArray = block.split(separator: ":")
        for t in 0...plaintextArray.count-1{
            let keyValue = UInt32(keyStreamArray[t], radix: 16)!
            let textValue = UInt32(plaintextArray[t], radix: 16)!
            let xOrEd = keyValue ^ textValue
            if (String(xOrEd, radix:16).count == 1){
                if encryptedMessage == ""{
                    encryptedMessage += "0" + String(xOrEd, radix:16)
                }else {
                    encryptedMessage += ":0" + String(xOrEd, radix:16)
                }
            }else {
                if encryptedMessage == ""{
                    encryptedMessage += String(xOrEd, radix:16)
                    
                } else {
                    encryptedMessage += ":" + String(xOrEd, radix:16)
                    
                }
            }
        }
    }
    return encryptedMessage
}

public func chachaDecryption(_ key: String, _ nonce: String, _ count: Int, _ cipherText: String) -> String{
    var decryptedMessage = ""
    var keyStream:String
    let chars = cipherText.split(separator:":")
    if (chars.count/64) > 0 {
        for j in 0...(chars.count/64)-1{
            keyStream = chacha20_block(key, nonce, count+j)
            var block: String = ""
            for i in 0...63{
                if block == ""{
                    block += chars[(j*64)+i]
                }else {
                    block += ":" + chars[(j*64)+i]
                }
            }
            let keyStreamArray = keyStream.split(separator: ":")
            let plaintextArray = block.split(separator: ":")
            for t in 0...keyStreamArray.count-1{
                let keyValue = UInt32(keyStreamArray[t], radix: 16)!
                let textValue = UInt32(plaintextArray[t], radix: 16)!
                let xOrEd = keyValue ^ textValue
                decryptedMessage += String(UnicodeScalar(xOrEd)!)
            }
        }
    }
    if (chars.count % 64) != 0{
        let index = chars.count/64
        keyStream = chacha20_block(key, nonce, count+index)
        var block: String = ""
        for i in 0...(chars.count-1)-(64*index){
            if block == ""{
                block += chars[(index*64)+i]
            }else {
                block += ":" + chars[(index*64)+i]
            }
        }
        let keyStreamArray = keyStream.split(separator: ":")
        let plaintextArray = block.split(separator: ":")
        for t in 0...plaintextArray.count-1{
            let keyValue = UInt32(keyStreamArray[t], radix: 16)!
            let textValue = UInt32(plaintextArray[t], radix: 16)!
            let xOrEd = keyValue ^ textValue
            decryptedMessage += String(UnicodeScalar(xOrEd)!)
        }
    }
    return decryptedMessage
}

public func poly1305(_ key: String, _ message: String, _ isPlaintext: Bool) -> String {
    var message = message
    var tag: String = ""
    var accumulator:BInt = 0
    let p:String = "3fffffffffffffffffffffffffffffffb"
    var hexedText = ""
    var rArray: [UInt32] = [UInt32](repeating: 0, count:16)
    var sArray: [UInt32] = [UInt32](repeating: 0, count:16)
    var r: String = ""
    var s: String = ""
    
    let keySplit = key.split(separator: ":")
    for i in 0...15{
        rArray[i] = UInt32(keySplit[i], radix:16)!
    }
    rArray[3]&=15
    rArray[7]&=15
    rArray[11] &= 15;
    rArray[15] &= 15;
    rArray[4] &= 252;
    rArray[8] &= 252;
    rArray[12] &= 252;
    
    for i in 0...15{
        var rSub = String(rArray[i], radix:16)
        if rSub.count == 1{
            rSub = "0" + rSub
        }
        r = rSub + r
    }
    
    for i in 0...15{
        sArray[i] = UInt32(keySplit[i+16], radix:16)!
    }
    for i in 0...15{
        var sSub = String(sArray[i], radix:16)
        if sSub.count == 1{
            sSub = "0" + sSub
        }
        s = sSub + s
    }
    
    if isPlaintext{
        for character in message.characters{
            let char = String(character).unicodeScalars
            if hexedText == ""{
                hexedText += String(char[char.startIndex].value, radix:16)
            } else {
                hexedText += ":" + String(char[char.startIndex].value, radix:16)
            }
        }
        message = hexedText
    }
    
    let chars = message.split(separator: ":")
    chars
    for j in 0 ... (chars.count/16) - 1 {
        var fixedBlock = ""
        for i in 0 ... 15 {
            fixedBlock = chars[(j*16)+i] + fixedBlock
        }
        fixedBlock = "01" + fixedBlock
        accumulator = accumulator + BInt(number:fixedBlock, withBase:16)
        accumulator = accumulator * BInt(number:r, withBase:16) % BInt(number:p, withBase:16)
    }
    
    if (chars.count % 16) != 0{
        let index = chars.count/16
        var fixedBlock = ""
        for i in 0 ... message.count%16-1 {
            fixedBlock = chars[(index*16)+i] + fixedBlock
        }
        fixedBlock = "01" + fixedBlock
        while fixedBlock.count < 16{
            fixedBlock = "0" + fixedBlock
        }
        accumulator = accumulator + BInt(number:fixedBlock, withBase:16)
        accumulator = accumulator * BInt(number:r, withBase:16) % BInt(number:p, withBase:16)
    }
    
    let tagInt = accumulator + BInt(number:s, withBase:16)
    let tag_s = tagInt.asString(withBase: 16)
    
    for i in 0...15{
        let start = tag_s.index(tag_s.startIndex, offsetBy: tag_s.count-(2*i)-2)
        let end = tag_s.index(tag_s.startIndex, offsetBy: tag_s.count-2*i)
        let range = start..<end
        if i<15{
            tag += tag_s.substring(with: range) + ":"
        } else {
            tag += tag_s.substring(with: range)
        }
    }
    return tag
}

public func poly1305_keyGeneration(_ key: String, nonce: String) -> String{
    let count = 0
    let block = chacha20_block(key, nonce, count)
    let end = block.index(block.startIndex, offsetBy: (31*3)+2)
    return block.substring(to:end)
}

public func AEAD(_ key: String, _ nonce: String, _ plaintext: String, _ additionalText: String?) -> String{
    let poly_key = poly1305_keyGeneration(key, nonce: nonce)
    var encryptedData = chachaEncryption(key, nonce, 1, plaintext)
    var aead = encryptedData
    let encryptedText = encryptedData.replacingOccurrences(of: ":", with: "")
    var message = ""
    var adLength = 0
    let cipherLength = encryptedText.count
    if additionalText != nil {
        message = additionalText!.replacingOccurrences(of: ":", with: "")
        adLength = message.count
        while (message.count % 16) != 0{
            message.append("0")
        }
    }
    message += encryptedText
    while (message.count % 32) != 0 {
        if (message.count % 2 == 0){
            encryptedData.append(":")
        }
        message.append("0")
        encryptedData.append("0")
    }
    var adOctet = String(adLength/2, radix:16)
    if adOctet.count == 1{
        adOctet = "0"+adOctet
    }
    while adOctet.count < 16 {
        adOctet += "0"
    }
    var adOctetString = ""
    let adOctetChars = Array(adOctet.characters)
    stride(from: 0, to: adOctetChars.count, by: 2).forEach {
        adOctetString += String(adOctetChars[$0..<min($0+2, adOctetChars.count)])
        if $0+2 < adOctetChars.count {
            adOctetString += ":"
        }
    }
    var cipherOctet = String(cipherLength/2, radix:16)
    if cipherOctet.count == 1{
        cipherOctet = "0"+cipherOctet
    }
    while cipherOctet.count < 16 {
        cipherOctet += "0"
    }
    var cipherOctetString = ""
    let cipherOctetChars = Array(cipherOctet.characters)
    stride(from: 0, to: cipherOctetChars.count, by: 2).forEach {
        cipherOctetString += String(cipherOctetChars[$0..<min($0+2, cipherOctetChars.count)])
        if $0+2 < cipherOctetChars.count {
            cipherOctetString += ":"
        }
    }
    encryptedData.append(":")
    encryptedData.append(adOctetString)
    encryptedData.append(":")
    encryptedData.append(cipherOctetString)
    
    let tag = poly1305(poly_key, encryptedData, false)
    aead.append("-")
    aead.append(tag)
    return aead
}

