//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler.decrypt
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler.encrypt
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler.generateKeyPair
import java.security.PublicKey

object EncryptForMultipleRecipients {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Generate the first recipient KeyPair
        val recipient1 = generateKeyPair()
        //Generate the second recipient KeyPair
        val recipient2 = generateKeyPair()
        //Create a List for the public keys
        val keys = ArrayList<PublicKey>()
        //Add the keys to the list
        keys.add(recipient1.public)
        keys.add(recipient2.public)
        //Encrypt data
        val encrypted = encrypt(plaintext.toByteArray(), keys)
        //Decrypt data for recipient 1
        val decrypted1 = String(decrypt(encrypted, recipient1.private))
        //Decrypt data for recipient 2
        val decrypted2 = String(decrypt(encrypted, recipient2.private))
        //plaintext == decrypted1 == decrypted2, and you only have to send or store one message that
        //both keys can decrypt
    }
}
