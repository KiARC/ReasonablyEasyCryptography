package com.katiearose.reasonablyEasyCryptography.asymmetric

import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


object PEMHandler {
    private val encoder: Base64.Encoder = Base64.getMimeEncoder()
    private val decoder: Base64.Decoder = Base64.getMimeDecoder()

    @JvmStatic
    fun keyPairToPem(keys: KeyPair): PEMPair {
        return PEMPair(keyToPem(keys.public), keyToPem(keys.private))
    }

    @JvmStatic
    fun keyToPem(key: Key): String {
        val encodedKey = String(encoder.encode(key.encoded))
        val algorithm = key.algorithm
        val type = if (key.javaClass.name.contains("private", true)) "PRIVATE" else "PUBLIC"
        return "-----BEGIN $algorithm $type KEY-----${System.lineSeparator()}$encodedKey${System.lineSeparator()}-----END $algorithm $type KEY-----"
    }

    @JvmStatic
    fun pemToKey(pem: String): Key {
        val split = pem.split(System.lineSeparator())
        val firstLine = split[0].split(" ")
        val type = if (firstLine[2].equals("PRIVATE", true)) 'r' else 'u'
        val slice = split.slice(1 until split.size - 1)
        val sliceString = slice.joinToString(System.lineSeparator())
        val decoded = decoder.decode(sliceString)
        val keyFactory = KeyFactory.getInstance(firstLine[1])
        return if (type == 'r') keyFactory.generatePrivate(PKCS8EncodedKeySpec(decoded)) else keyFactory.generatePublic(
            X509EncodedKeySpec(decoded)
        )
    }

    @JvmStatic
    fun pemPairToKeyPair(pem: PEMPair): KeyPair {
        val public = pemToKey(pem.public)
        val private = pemToKey(pem.private)
        return KeyPair(public as PublicKey, private as PrivateKey)
    }
}