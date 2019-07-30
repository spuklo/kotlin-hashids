package org.hashids

class Hashids2(salt: String = defaultSalt,
               length: Int = defaultMinimalHashLength,
               userAlphabet: String = defaultAlphabet) {
    companion object {
        const val defaultSalt = ""
        const val defaultMinimalHashLength = 0
        const val defaultAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

        const val defaultSeparators = "cfhistuCFHISTU"
        const val minimalAlphabetLength = 16
        const val separatorDiv = 3.5
        const val guardDiv = 12
    }

    val version = "1.0.0"

    private val effectiveSalt = whatSalt(salt)
    private val effectiveHashLength = whatHashLength(length)
    val effectiveAlphabet = whatAlphabet(userAlphabet)

    fun encode(number: Long) = "TODO"

    fun decode(hash: String): LongArray {
        return LongArray(0)
    }

    fun encodeHex(hex: String) = "TODO"

    fun decodeHex(hash: String) = "TODO"

    private fun whatSalt(aSalt: String) = when {
        aSalt.isEmpty() -> defaultSalt
        else -> aSalt
    }

    private fun whatHashLength(aLength: Int) = when {
        aLength > 0 -> aLength
        else -> defaultMinimalHashLength
    }

    private fun whatAlphabet(userAlphabet: String): String {
        val uniqueAlphabet = unique(userAlphabet)
        if (uniqueAlphabet.length < minimalAlphabetLength) {
            throw IllegalArgumentException("alphabet must contain at least $minimalAlphabetLength unique characters")
        }
        if (uniqueAlphabet.contains(" ")) {
            throw IllegalArgumentException("alphabet cannot contains spaces")
        }

        val legalSeparators = defaultSeparators.toSet().intersect(uniqueAlphabet.toSet())
        val alphabetWithoutSeparators = uniqueAlphabet.toSet().minus(legalSeparators).joinToString("")
        val shuffledSeparators = consistentShuffle(legalSeparators.joinToString(""), effectiveSalt)

        if (shuffledSeparators.isEmpty() ||
                (alphabetWithoutSeparators.length / shuffledSeparators.length).toFloat() > separatorDiv) {

        }

        return "TODO"
    }

    private fun consistentShuffle(alphabet: String, salt: String) = when {
        salt.isEmpty() -> alphabet
        else -> {
            val initial = ShuffleData(alphabet.toCharArray(), salt, 0, 0)
            shuffle(initial, alphabet.length - 1, 1).alphabet.joinToString("")
        }
    }

    private fun unique(input: String) = input.toSet().joinToString("")
}

private tailrec fun shuffle(data: ShuffleData, currentPosition: Int, limit: Int): ShuffleData = when {
    currentPosition < limit -> data
    else -> {
        val saltReminder = data.saltReminder.rem(data.salt.length)
        val asciiValue = data.salt[saltReminder].toInt()
        val cumulativeValue = data.cumulative + asciiValue
        val positionToSwap = (asciiValue + saltReminder + cumulativeValue) % currentPosition
        data.alphabet[positionToSwap] = data.alphabet[currentPosition].also {
            data.alphabet[currentPosition] = data.alphabet[positionToSwap]
        }
        shuffle(ShuffleData(data.alphabet, data.salt, cumulativeValue, saltReminder + 1), currentPosition - 1, limit)
    }
}

private data class AlphabetAndSeparators(val alphabet: String, val separators: String)

private data class ShuffleData(val alphabet: CharArray, val salt: String, val cumulative: Int, val saltReminder: Int) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ShuffleData

        if (!alphabet.contentEquals(other.alphabet)) return false
        if (salt != other.salt) return false
        if (cumulative != other.cumulative) return false
        if (saltReminder != other.saltReminder) return false

        return true
    }

    override fun hashCode(): Int {
        var result = alphabet.contentHashCode()
        result = 31 * result + salt.hashCode()
        result = 31 * result + cumulative
        result = 31 * result + saltReminder
        return result
    }
}
