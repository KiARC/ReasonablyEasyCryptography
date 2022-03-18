package reasonablyEasyCryptography

import java.nio.ByteBuffer
import java.security.*
import javax.crypto.Cipher

class AsymmetricEncryptionHandler {
    companion object {
        @JvmStatic
        fun generateKeyPair(keySize: Int = 2048): KeyPair {
                val gen: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
                gen.initialize(keySize)
                return gen.generateKeyPair()
        }
        fun encrypt(data: ByteArray, key: PublicKey): ByteArray {
            val k = SymmetricEncryptionHandler.generateKey(128)
            val encryptedData = SymmetricEncryptionHandler.encrypt(data, k)
            val c = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")
            c.init(Cipher.ENCRYPT_MODE, key)
            val kEnc = c.doFinal(k.encoded)
            val output = ByteBuffer.allocate(kEnc.size + encryptedData.size)
            output.put(kEnc)
            output.put(encryptedData)
            return output.array()
        }
        fun decrypt(data: ByteArray, key: PrivateKey): ByteArray {
            val c = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            c.init(Cipher.DECRYPT_MODE, key)
            val buffer = ByteBuffer.wrap(data)
            val kB = ByteArray(256)
            buffer.get(kB)
            val enc = ByteArray(buffer.remaining())
            buffer.get(enc)
            val k = SymmetricEncryptionHandler.assembleKey(c.doFinal(kB))
            return SymmetricEncryptionHandler.decrypt(enc, k)
        }
        fun sign(data: ByteArray, key: PrivateKey): ByteArray {
            val s = Signature.getInstance("SHA256withRSA")
            s.initSign(key)
            s.update(data)
            return s.sign()
        }
        fun verify(data: ByteArray, sig: ByteArray, key: PublicKey): Boolean {
            val s = Signature.getInstance("SHA256withRSA")
            s.initVerify(key)
            s.update(data)
            return s.verify(sig)
        }
        fun encryptAndSign(data: ByteArray, encryptionKey: PublicKey, signingKey: PrivateKey): Pair<ByteArray, ByteArray> {
            val enc = encrypt(data, encryptionKey)
            val sig = sign(enc, signingKey)
            return Pair(enc, sig)
        }
        @JvmStatic
        fun decryptAndVerify(data: ByteArray, sig: ByteArray, decryptionKey: PrivateKey, verificationKey: PublicKey, exceptionOnFailure: Boolean = true): ByteArray? {
            return if (verify(data, sig, verificationKey)) decrypt(data, decryptionKey)
            else if (exceptionOnFailure) throw SecurityException("Signature verification failed.")
            else null
        }
    }
}