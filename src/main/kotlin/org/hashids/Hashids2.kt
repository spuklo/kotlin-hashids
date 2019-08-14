package org.hashids

import java.lang.Long.toHexString
import java.util.ArrayList
import kotlin.math.ceil
import kotlin.math.pow

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

    fun encode(vararg numbers: Long): String = when {
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

    private fun addGuardsIfNecessary(encodedString: String, numbersHash: Int): String =
            if (encodedString.length < finalHashLength) {
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
    fun encodeHex(hex: String): String = when {
        !hex.matches("^[0-9a-fA-F]+$".toRegex()) -> emptyString
        else -> {
            val toEncode = "[\\w\\W]{1,12}".toRegex().findAll(hex)
                    .map { it.groupValues }
                    .flatten()
                    .map { it.toLong(16) }
                    .toList()
                    .toLongArray()
            encode(*toEncode)
        }
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

    private fun hash(input: Long, alphabet: String): String =
            doHash(input, alphabet.toCharArray(), HashData(emptyString, input)).hash

    private tailrec fun doHash(number: Long, alphabet: CharArray, data: HashData): HashData = when {
        data.current > 0 -> {
            val newHashCharacter = alphabet[(data.current % alphabet.size.toLong()).toInt()]
            val newCurrent = data.current / alphabet.size
            doHash(number, alphabet, HashData("$newHashCharacter${data.hash}", newCurrent))
        }
        else -> data
    }

    private fun unhash(input: String, alphabet: String): Long =
            doUnhash(input.toCharArray(), alphabet, alphabet.length.toDouble(), 0, 0)

    private tailrec fun doUnhash(input: CharArray, alphabet: String, alphabetLengthDouble: Double, currentNumber: Long, currentIndex: Int): Long =
            when {
                currentIndex < input.size -> {
                    val position = alphabet.indexOf(input[currentIndex])
                    val newNumber = currentNumber + (position * alphabetLengthDouble.pow((input.size - currentIndex - 1))).toLong()
                    doUnhash(input, alphabet, alphabetLengthDouble, newNumber, currentIndex + 1)
                }
                else -> currentNumber
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
        when {
            uniqueAlphabet.length < minimalAlphabetLength -> throw IllegalArgumentException("alphabet must contain at least $minimalAlphabetLength unique characters")
            uniqueAlphabet.contains(" ") -> throw IllegalArgumentException("alphabet cannot contains spaces")
            else -> {
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
        }
    }

    private fun adjustAlphabetAndSeparators(alphabetWithoutSeparators: String, shuffledSeparators: String): AlphabetAndSeparators =
            if (shuffledSeparators.isEmpty() ||
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

    private fun unique(input: String) = input.toSet().joinToString(emptyString)

    private tailrec fun initialEncode(numbers: List<Long>,
                                      salt: String,
                                      separators: CharArray,
                                      bufferSeed: String,
                                      currentIndex: Int,
                                      alphabet: String,
                                      currentReturnString: String): String = when {
        currentIndex < numbers.size -> {
            val currentNumber = numbers[currentIndex]
            val buffer = "$bufferSeed$salt$alphabet"
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

private data class HashData(val hash: String, val current: Long)