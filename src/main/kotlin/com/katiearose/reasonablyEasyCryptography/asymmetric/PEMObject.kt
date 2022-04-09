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