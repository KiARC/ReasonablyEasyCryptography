//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler;
import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMObject;
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class PemAndUnPemAWholeBunchOfKeys {
    public static void main(String[] args) {
        //This code doesn't pertain as much to the actual example, but I need a
        //list of keys and decided this would be a good way to do it
        ArrayList<Key> keys = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            KeyPair k = RSAHandler.generateKeyPair();
            keys.add(k.getPrivate());
            keys.add(k.getPublic());
        }
        //Now that we have a list of 20 keys (10 private and 10 public) we can get started
        //Define a StringBuilder to add the keys to
        StringBuilder builder = new StringBuilder();
        //First, loop over the keys and convert them all to PEMs, then put those PEMs into our StringBuilder
        for (Key key : keys) {
            builder.append(PEMHandler.keyToPem(key)).append(System.lineSeparator());
        }
        //Now we convert the builder to a string, like what you might read from a file full of keys
        String PEMList = builder.toString();
        //Initialize the List where we'll store the unpemed keys
        ArrayList<Key> keysUnpemed = new ArrayList<>();
        //Use the handy parsePemStream function to parse all of the PEMs in the String in one call
        List<PEMObject> p = PEMHandler.parsePemStream(new ByteArrayInputStream(PEMList.getBytes()));
        //Loop over the new PEMObjects and unpem them
        for (int i = 0; i < keys.size(); i++) {
            PEMObject it = p.get(i);
            keysUnpemed.add(PEMHandler.pemToKey(it));
        }
        //keysUnpemed now contains all the same keys as keys
    }
}
