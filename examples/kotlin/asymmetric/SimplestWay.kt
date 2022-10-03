//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler

object SimplestWay {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Generate a KeyPair, you can specify a keysize but the default (2048) is fine
        val keys = RSAHandler.generateKeyPair()
        //Encrypt and sign plaintext using keys. Usually you'd use someone else's
        //public key for encryption and then send the encrypted data to them but
        //in this example I'll just use one keypair for convenience
        val sdc = RSAHandler.encryptAndSign(plaintext.toByteArray(), keys.public, keys.private)
        //Decrypt and verify ciphertext and signature in the SignedDataContainer.
        //This method wil throw an exception if the signature is bad unless you
        //explicitly tell it not to by setting the exceptionOnFailure flag to false,
        //in which case it will just return null. If you don't actually care about the
        //signature, just decrypt it outright, don't bother checking unless the validity matters.
        //You can also pass the data and the signature separately but a SignedDataContainer makes life easier.
        val decrypted = String(RSAHandler.decryptAndVerify(sdc, keys.private, keys.public)!!)
    }
}
