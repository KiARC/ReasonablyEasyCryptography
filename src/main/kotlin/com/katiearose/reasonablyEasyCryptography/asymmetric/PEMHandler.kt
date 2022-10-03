//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with Foobar. If not, see <https://www.gnu.org/licenses/>.

package com.katiearose.reasonablyEasyCryptography.asymmetric

import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


object PEMHandler {
    private val encoder: Base64.Encoder = Base64.getMimeEncoder()
    private val decoder: Base64.Decoder = Base64.getMimeDecoder()

    /**
     * Wrapper method around keyToPem() that parses a whole KeyPair automatically
     *
     * @author Katherine Rose
     * @param keys the KeyPair to parse
     * @return a PEMPair containing the PEM data for each of the keys in the KeyPair
     */
    @JvmStatic
    fun keyPairToPem(keys: KeyPair): PEMPair {
        return PEMPair(keyToPem(keys.public), keyToPem(keys.private))
    }

    /**
     * Encodes a Key to a PEM Object
     *
     * Automatically detects the algorithm and whether the key is public or private, then assembles a PEM String
     *
     * @author Katherine Rose
     * @param key the Key to parse
     * @return the PEM data for the key
     */
    @JvmStatic
    fun keyToPem(key: Key): PEMObject {
        val encodedKey = String(encoder.encode(key.encoded))
        val algorithm = key.algorithm
        val type = if (key.format == "PKCS#8") "PRIVATE" else "PUBLIC"
        return PEMObject("", algorithm, type, encodedKey)
    }

    /**
     * Assembles a Key from a PEM Object
     *
     * Automatically detects the algorithm and whether the key is public or private, then assembles a Key from the encoded data
     *
     * @author Katherine Rose
     * @param pem the PEM data to parse
     * @return a new Key, either a PublicKey or a PrivateKey depending on the data passed to it.
     */
    @JvmStatic
    fun pemToKey(pem: PEMObject): Key {
        val decoded = decoder.decode(pem.data)
        val keyFactory = KeyFactory.getInstance(pem.algorithm)
        return if (pem.type.equals(
                "PRIVATE",
                true
            )
        ) keyFactory.generatePrivate(PKCS8EncodedKeySpec(decoded)) else keyFactory.generatePublic(
            X509EncodedKeySpec(decoded)
        )
    }

    /**
     * Wrapper method around pemToKey() that parses a whole PEMPair automatically
     *
     * @author Katherine Rose
     * @param pem the PEMPair to parse
     * @return a KeyPair derived from the PEM data contained in the PEMPair
     */
    @JvmStatic
    fun pemPairToKeyPair(pem: PEMPair): KeyPair {
        val public = pemToKey(pem.public)
        val private = pemToKey(pem.private)
        return KeyPair(public as PublicKey, private as PrivateKey)
    }

    @JvmStatic
    fun stringToPemObject(input: String): PEMObject {
        val lines = ArrayDeque(input.split(System.lineSeparator()))
        var data = ""
        while (!lines.peek().contains("-----BEGIN")) {
            lines.pop()
        }
        val header = lines.pop().split(" ")
        val algorithm = header[1]
        val type = header[2]
        while (!lines.peek().contains("-----END")) {
            data += lines.pop()
        }
        return PEMObject("", algorithm, type, data)
    }

    @JvmStatic
    fun parsePemStream(input: ByteArrayInputStream): List<PEMObject> {
        val reader = InputStreamReader(input)
        val lines = ArrayDeque(reader.readLines())
        val readPems = ArrayDeque<PEMObject>()
        while (lines.isNotEmpty()) {
            var next = ""
            while (!lines.peek().contains("-----BEGIN")) {
                lines.pop()
            }
            next += "${lines.pop()}${System.lineSeparator()}"
            while (!lines.peek().contains("-----END")) {
                next += "${lines.pop()}${System.lineSeparator()}"
            }
            next += "${lines.pop()}${System.lineSeparator()}"
            readPems.add(stringToPemObject(next))
        }
        return readPems.toList()
    }
}