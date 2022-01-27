import java.nio.charset.Charset
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator


fun main(args: Array<String>) {

    //DES
    val keyGen = KeyGenerator.getInstance("DES")
    val random = SecureRandom()
    keyGen.init(random)

    val des = Cipher.getInstance("DES")
    val key = keyGen.generateKey()

    des.init(Cipher.ENCRYPT_MODE, key)

    println("Encrypting the message \"This is fun\" using DES with the following key:")
    println(key.encoded.toUByteArray().joinToString(separator = "") { it.toString(16).padStart(2,'0') })

    val cipherText = applySymmetricCipher(des, "This is fun".toByteArray())

    println("The encrypted text (as hexadecimal) is: ")
    println(cipherText.toUByteArray().joinToString(separator = "") { it.toString(16) })
    println("The encrypted text (as ASCII) is: ")
    println(cipherText.toString(Charset.forName("ASCII")))

    val desDecrypt = Cipher.getInstance("DES")
    desDecrypt.init(Cipher.DECRYPT_MODE, key)

    val decrypted = applySymmetricCipher(desDecrypt, cipherText)

    println("The decrypted text is: ")
    println(decrypted.toString(Charset.forName("ASCII")))

    println()
    println()



    //RSA
    val pairGenerator = KeyPairGenerator.getInstance("RSA")

    pairGenerator.initialize(512, random)

    val keyPair = pairGenerator.generateKeyPair()

    val publicKey = keyPair.public

    val privateKey = keyPair.private

    val rsa = Cipher.getInstance("RSA")

    rsa.init(Cipher.ENCRYPT_MODE, publicKey)

    println("Encrypting the message \"This is fun\" using RSA with the following public key:")
    println(publicKey.encoded.toUByteArray().joinToString(separator = "") { it.toString(16).padStart(2,'0') })

    val rsaCipherText = rsa.update("This is fun".toByteArray()).toTypedArray().toMutableList().let {
        it.addAll(rsa.doFinal().toTypedArray())
        it.toByteArray()
    }

    println("The encrypted text (as hexadecimal) is: ")
    println(rsaCipherText.toUByteArray().joinToString(separator = "") { it.toString(16) })
    println("The encrypted text (as ASCII) is: ")
    println(rsaCipherText.toString(Charset.forName("ASCII")))

    val rsaDecrypt = Cipher.getInstance("RSA")
    rsaDecrypt.init(Cipher.DECRYPT_MODE, privateKey)
    val decryptedRsa = rsaDecrypt.update(rsaCipherText).toTypedArray().toMutableList().let {
        it.addAll(rsaDecrypt.doFinal().toTypedArray())
        it.toByteArray()
    }

    println("Using the private key:")
    println(privateKey.encoded.toUByteArray().joinToString(separator = "") { it.toString(16).padStart(2,'0') })
    println("The decrypted text is: ")
    println(decryptedRsa.toString(Charset.forName("ASCII")))
}


fun applySymmetricCipher(cipher: Cipher, plainText: ByteArray): ByteArray {
    val blockSize = cipher.blockSize
    val numberOfBlocks = kotlin.math.ceil((plainText.size.toDouble() / blockSize.toDouble())).toInt()
    val outputSize = cipher.getOutputSize(blockSize)

    val cipherText = arrayListOf<Byte>()

    for (i in 0..numberOfBlocks) {
        val beginningIndex = i*blockSize
        val endIndex = ((i+1)*blockSize)

        if (endIndex <= plainText.size) {
            val nextPlainBlock = plainText.slice(beginningIndex until endIndex).toByteArray()
            val nextCipherBlock = ByteArray(blockSize)
            cipher.update(nextPlainBlock, 0, blockSize, nextCipherBlock)
            cipherText.addAll(nextCipherBlock.toTypedArray())
            if (endIndex == plainText.size) {
                cipher.doFinal()
            }
        }
        else {
            val nextPlainBlock = plainText.slice(beginningIndex until plainText.size).toByteArray()
            val nextCipherBlock = cipher.doFinal(nextPlainBlock, 0, nextPlainBlock.size)
            cipherText.addAll(nextCipherBlock.toTypedArray())
        }

    }
    return cipherText.toByteArray()
}

