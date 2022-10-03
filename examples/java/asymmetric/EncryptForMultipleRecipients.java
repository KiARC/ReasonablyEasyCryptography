//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;

public class EncryptForMultipleRecipients {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Generate the first recipient KeyPair
        KeyPair recipient1 = RSAHandler.generateKeyPair();
        //Generate the second recipient KeyPair
        KeyPair recipient2 = RSAHandler.generateKeyPair();
        //Create a List for the public keys
        ArrayList<PublicKey> keys = new ArrayList<>();
        //Add the keys to the list
        keys.add(recipient1.getPublic());
        keys.add(recipient2.getPublic());
        //Encrypt data
        byte[] encrypted = RSAHandler.encrypt(plaintext.getBytes(), keys);
        //Decrypt data for recipient 1
        String decrypted1 = new String(RSAHandler.decrypt(encrypted, recipient1.getPrivate()));
        //Decrypt data for recipient 2
        String decrypted2 = new String(RSAHandler.decrypt(encrypted, recipient2.getPrivate()));
        //plaintext == decrypted1 == decrypted2, and you only have to send or store one message that
        //both keys can decrypt
    }
}
