//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler
import java.io.ByteArrayInputStream
import java.security.Key

object PemAndUnPemAWholeBunchOfKeys {
    @JvmStatic
    fun main(args: Array<String>) {
        //This code doesn't pertain as much to the actual example, but I need a
        //list of keys and decided this would be a good way to do it
        val keys = ArrayList<Key>()
        for (i in 1..10) {
            val k = RSAHandler.generateKeyPair()
            keys.add(k.private)
            keys.add(k.public)
        }
        //Now that we have a list of 20 keys (10 private and 10 public) we can get started
        //Define a StringBuilder to add the keys to
        val builder = StringBuilder()
        //First, loop over the keys and convert them all to PEMs, then put those PEMs into our StringBuilder
        for (key in keys) {
            builder.append(PEMHandler.keyToPem(key)).append(System.lineSeparator())
        }
        //Now we convert the builder to a string, like what you might read from a file full of keys
        val PEMList = builder.toString()
        //Initialize the List where we'll store the unpemed keys
        val keysUnpemed = ArrayList<Key>()
        //Use the handy parsePemStream function to parse all of the PEMs in the String in one call
        val p = PEMHandler.parsePemStream(ByteArrayInputStream(PEMList.toByteArray()))
        //Loop over the new PEMObjects and unpem them
        for (i in keys.indices) {
            val it = p[i]
            keysUnpemed.add(PEMHandler.pemToKey(it))
        }
        //keysUnpemed now contains all the same keys as keys
    }
}
