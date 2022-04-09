package com.katiearose.reasonablyEasyCryptography.asymmetric

data class PEMPair(val public: String, val private: String) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PEMPair

        if (private != other.private) return false
        if (public != other.public) return false

        return true
    }

    override fun hashCode(): Int {
        var result = private.hashCode()
        result = 31 * result + public.hashCode()
        return result
    }
}