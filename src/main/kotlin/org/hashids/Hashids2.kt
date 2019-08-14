@file:Suppress("DuplicatedCode")

package org.hashids

import java.lang.Long.toHexString
import java.util.ArrayList
import java.util.regex.Pattern
import kotlin.math.ceil

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
        private const val emptyString = ""
        private const val maxNumber = 9007199254740992
    }

    private val finalSalt = whatSalt(salt)
    private val finalHashLength = whatHashLength(length)
    private val alphabetSeparatorsAndGuards = calculateAlphabetAndSeparators(userAlphabet)
    private val finalAlphabet = alphabetSeparatorsAndGuards.alphabet
    private val finalSeparators = alphabetSeparatorsAndGuards.separators
    private val finalGuards = alphabetSeparatorsAndGuards.guards

    val version = "1.0.0"

    fun encode(vararg numbers: Long) = when {
        numbers.isEmpty() -> emptyString
        numbers.any { it > maxNumber } -> throw IllegalArgumentException("Number can not be greater than ${maxNumber}L")
        else -> {
            val numbersHash = numbers.indices
                    .map { (numbers[it].rem((it + 100))).toInt() }
                    .sum()

            val initialCharacter = finalAlphabet.toCharArray()[numbersHash.rem(finalAlphabet.length)]
            val encodedString = initialEncode(numbers.asList(), finalSalt, finalSeparators.toCharArray(), "$initialCharacter", 0, finalAlphabet, "$initialCharacter")
            val tempReturnString = addGuardsIfNecessary(encodedString, numbersHash)
            val halfLength = finalAlphabet.length / 2
            val alphabet = consistentShuffle(finalAlphabet, finalAlphabet)

            ensureMinimalLength(halfLength, alphabet, tempReturnString)
        }
    }

    private fun guardIndex(numbersHash: Int, returnString: String, index: Int): Int = (numbersHash + returnString.toCharArray()[index].toInt()).rem(finalGuards.length)

    private fun addGuardsIfNecessary(encodedString: String, numbersHash: Int): String = if (encodedString.length < finalHashLength) {
        val guard0 = finalGuards.toCharArray()[guardIndex(numbersHash, encodedString, 0)]
        val retString = guard0.plus(encodedString)

        if (retString.length < finalHashLength) {
            val guard2 = finalGuards.toCharArray()[guardIndex(numbersHash, retString, 2)]
            retString.plus(guard2)
        } else {
            retString
        }
    } else {
        encodedString
    }


    /**
     * Decrypt string to numbers
     *
     * @param hash the encrypt string
     * @return Decrypted numbers
     */
    fun decode(hash: String): LongArray {
        if (hash == "")
            return LongArray(0)

        var alphabet = finalAlphabet
        val retArray = ArrayList<Long>()

        var i = 0
        val regexp = "[$finalGuards]".toRegex()
        var hashBreakdown = hash.replace(regexp, " ")
        var hashArray = hashBreakdown.split(" ")

        if (hashArray.size == 3 || hashArray.size == 2) {
            i = 1
        }

        hashBreakdown = hashArray[i]

        val lottery = hashBreakdown.toCharArray()[0]

        hashBreakdown = hashBreakdown.substring(1)
        hashBreakdown = hashBreakdown.replace("[$finalSeparators]".toRegex(), " ")
        hashArray = hashBreakdown.split(" ")

        var buffer: String
        for (subHash in hashArray) {
            buffer = lottery + finalSalt + alphabet
            alphabet = consistentShuffle(alphabet, buffer.substring(0, alphabet.length))
            retArray.add(unhash(subHash, alphabet))
        }

        var arr = LongArray(retArray.size)
        for (index in retArray.indices) {
            arr[index] = retArray[index]
        }

        if (encode(*arr) != hash) {
            arr = LongArray(0)
        }

        return arr
    }

    /**
     * Encrypt hex string to string
     *
     * @param hex the hex string to encrypt
     * @return The encrypted string
     */
    fun encodeHex(hex: String): String { // TODO re-implement from scratch + add tests
        if (!hex.matches("^[0-9a-fA-F]+$".toRegex()))
            return emptyString

        val matched = ArrayList<Long>()
        val matcher = Pattern.compile("[\\w\\W]{1,12}").matcher(hex)

        while (matcher.find())
            matched.add(java.lang.Long.parseLong("1" + matcher.group(), 16))

        val result = LongArray(matched.size)
        for (i in matched.indices) result[i] = matched[i]

        return encode()
    }

    /**
     * Decrypt string to numbers
     *
     * @param hash the encrypt string
     * @return Decrypted numbers
     */
    fun decodeHex(hash: String): String = decode(hash)
            .map { toHexString(it).substring(1) }
            .toString()

    private fun hash(input: Long, alphabet: String): String {
        var current = input
        var hash = ""
        val length = alphabet.length
        val array = alphabet.toCharArray()

        do {
            hash = array[(current % length.toLong()).toInt()] + hash
            current /= length
        } while (current > 0)

        return hash
    }

    private fun unhash(input: String, alphabet: String): Long {
        var number: Long = 0
        var position: Long
        val inputArray = input.toCharArray()
        val length = input.length - 1

        for (i in 0..length) {
            position = alphabet.indexOf(inputArray[i]).toLong()
            number += (position.toDouble() * Math.pow(alphabet.length.toDouble(), (input.length - i - 1).toDouble())).toLong()
        }

        return number
    }

    private fun whatSalt(aSalt: String) = when {
        aSalt.isEmpty() -> defaultSalt
        else -> aSalt
    }

    private fun whatHashLength(aLength: Int) = when {
        aLength > 0 -> aLength
        else -> defaultMinimalHashLength
    }

    private fun calculateAlphabetAndSeparators(userAlphabet: String): AlphabetAndSeparators {
        val uniqueAlphabet = unique(userAlphabet)
        if (uniqueAlphabet.length < minimalAlphabetLength) {
            throw IllegalArgumentException("alphabet must contain at least $minimalAlphabetLength unique characters")
        }
        if (uniqueAlphabet.contains(" ")) {
            throw IllegalArgumentException("alphabet cannot contains spaces")
        }

        val legalSeparators = defaultSeparators.toSet().intersect(uniqueAlphabet.toSet())
        val alphabetWithoutSeparators = uniqueAlphabet.toSet().minus(legalSeparators).joinToString(emptyString)
        val shuffledSeparators = consistentShuffle(legalSeparators.joinToString(emptyString), finalSalt)

        val (adjustedAlphabet, adjustedSeparators) = adjustAlphabetAndSeparators(alphabetWithoutSeparators, shuffledSeparators)

        val guardCount = ceil(adjustedAlphabet.length.toDouble() / guardDiv).toInt()
        return if (adjustedAlphabet.length < 3) {
            val guards = adjustedSeparators.substring(0, guardCount)
            val seps = adjustedSeparators.substring(guardCount)
            AlphabetAndSeparators(adjustedAlphabet, seps, guards)
        } else {
            val guards = adjustedAlphabet.substring(0, guardCount)
            val alphabet = adjustedAlphabet.substring(guardCount)
            AlphabetAndSeparators(alphabet, adjustedSeparators, guards)
        }
    }

    private fun adjustAlphabetAndSeparators(alphabetWithoutSeparators: String,
                                            shuffledSeparators: String): AlphabetAndSeparators {

        return if (shuffledSeparators.isEmpty() ||
                (alphabetWithoutSeparators.length / shuffledSeparators.length).toFloat() > separatorDiv) {

            val sepsLength = calculateSeparatorsLength(alphabetWithoutSeparators)

            if (sepsLength > shuffledSeparators.length) {
                val difference = sepsLength - shuffledSeparators.length
                val seps = shuffledSeparators.plus(alphabetWithoutSeparators.substring(0, difference))
                val alpha = alphabetWithoutSeparators.substring(difference)
                AlphabetAndSeparators(consistentShuffle(alpha, finalSalt), seps)
            } else {
                val seps = shuffledSeparators.substring(0, sepsLength)
                AlphabetAndSeparators(consistentShuffle(alphabetWithoutSeparators, finalSalt), seps)
            }
        } else {
            AlphabetAndSeparators(consistentShuffle(alphabetWithoutSeparators, finalSalt), shuffledSeparators)
        }
    }

    private fun calculateSeparatorsLength(alphabet: String): Int = when (val s = ceil(alphabet.length / separatorDiv).toInt()) {
        1 -> 2
        else -> s
    }

    private fun consistentShuffle(alphabet: String, salt: String) = when {
        salt.isEmpty() -> alphabet
        else -> {
            val initial = ShuffleData(alphabet.toList(), salt, 0, 0)
            shuffle(initial, alphabet.length - 1, 1).alphabet.joinToString(emptyString)
        }
    }

    private fun unique(input: String) = input.toSet().joinToString(emptyString)

    private tailrec fun shuffle(data: ShuffleData, currentPosition: Int, limit: Int): ShuffleData = when {
        currentPosition < limit -> data
        else -> {
            val currentAlphabet = data.alphabet.toCharArray()
            val saltReminder = data.saltReminder.rem(data.salt.length)
            val asciiValue = data.salt[saltReminder].toInt()
            val cumulativeValue = data.cumulative + asciiValue
            val positionToSwap = (asciiValue + saltReminder + cumulativeValue).rem(currentPosition)
            currentAlphabet[positionToSwap] = currentAlphabet[currentPosition].also {
                currentAlphabet[currentPosition] = currentAlphabet[positionToSwap]
            }
            shuffle(ShuffleData(currentAlphabet.toList(), data.salt, cumulativeValue, saltReminder + 1), currentPosition - 1, limit)
        }
    }

    private tailrec fun initialEncode(numbers: List<Long>,
                                      salt: String,
                                      separators: CharArray,
                                      bufferSeed: String,
                                      currentIndex: Int,
                                      alphabet: String,
                                      currentReturnString: String): String = when {
        currentIndex < numbers.size -> {
            val currentNumber = numbers[currentIndex]
            val buffer = bufferSeed.plus(salt).plus(alphabet) // use string interpolation?
            val nextAlphabet = consistentShuffle(alphabet, buffer.substring(0, alphabet.length))
            val last = hash(currentNumber, nextAlphabet)

            val newReturnString = if (currentIndex + 1 < numbers.size) {
                val nextNumber = currentNumber.rem((last.toCharArray()[0].toInt() + currentIndex))
                val sepsIndex = (nextNumber.rem(separators.size)).toInt()
                currentReturnString.plus(last).plus(separators[sepsIndex])
            } else {
                currentReturnString.plus(last)
            }
            initialEncode(numbers, salt, separators, bufferSeed, currentIndex + 1, nextAlphabet, newReturnString)
        }
        else -> currentReturnString
    }

    private tailrec fun ensureMinimalLength(halfLength: Int, alphabet: String, returnString: String): String = when {
        returnString.length < finalHashLength -> {
            val tempReturnString = alphabet.substring(halfLength) + returnString + alphabet.substring(0, halfLength)
            val excess = tempReturnString.length - finalHashLength
            val newReturnString = if (excess > 0) {
                val position = excess / 2
                tempReturnString.substring(position, position + finalHashLength)
            } else {
                tempReturnString
            }
            ensureMinimalLength(halfLength, alphabet, newReturnString)
        }
        else -> returnString
    }

}

private data class AlphabetAndSeparators(val alphabet: String, val separators: String, val guards: String = "")
private data class ShuffleData(val alphabet: List<Char>, val salt: String, val cumulative: Int, val saltReminder: Int)
