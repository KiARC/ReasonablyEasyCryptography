//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler;

import java.security.KeyPair;

public class EncryptionAndDecryption {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Generate a KeyPair
        KeyPair keys = RSAHandler.generateKeyPair();
        //Encrypt data
        byte[] encrypted = RSAHandler.encrypt(plaintext.getBytes(), keys.getPublic());
        //Decrypt data
        String decrypted = new String(RSAHandler.decrypt(encrypted, keys.getPrivate()));
    }
}
