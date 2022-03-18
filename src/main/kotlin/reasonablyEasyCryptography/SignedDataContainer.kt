package reasonablyEasyCryptography

data class SignedDataContainer(val data: ByteArray, val signature: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignedDataContainer

        if (!data.contentEquals(other.data)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}
