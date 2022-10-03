//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with Foobar. If not, see <https://www.gnu.org/licenses/>.

package com.katiearose.reasonablyEasyCryptography.asymmetric

data class PEMObject(val comments: String = "", val algorithm: String, val type: String, val data: String) {
    override fun toString(): String {
        return "$comments${if (comments != "") System.lineSeparator() else ""}-----BEGIN $algorithm $type KEY-----${System.lineSeparator()}$data${System.lineSeparator()}-----END $algorithm $type KEY-----"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PEMObject

        if (comments != other.comments) return false
        if (algorithm != other.algorithm) return false
        if (type != other.type) return false
        if (data != other.data) return false

        return true
    }

    override fun hashCode(): Int {
        var result = comments.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + data.hashCode()
        return result
    }
}