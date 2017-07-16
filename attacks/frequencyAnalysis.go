package attacks

import (
	"math"
	"unicode"
	"unicode/utf8"
)

// from https://en.wikipedia.org/wiki/Letter_frequency
var engFreq = map[rune]float64{
	'a': .08167,
	'b': .01492,
	'c': .02782,
	'd': .04253,
	'e': .12702,
	'f': .02228,
	'g': .02015,
	'h': .06094,
	'i': .06996,
	'j': .00153,
	'k': .00772,
	'l': .04025,
	'm': .02406,
	'n': .06749,
	'o': .07507,
	'p': .01929,
	'q': .00095,
	'r': .05987,
	's': .06327,
	't': .09056,
	'u': .02758,
	'v': .00978,
	'w': .02360,
	'x': .00150,
	'y': .01974,
	'z': .00074,
}

// CharacterFrequencyScore measures how closely a text's letter frequency
// matches typical English.
// Added some secret sauce to increase the scores of unlikely plaintexts...
// Cryptopals Set 1, Challenge 3
// https://cryptopals.com/sets/1/challenges/3
func CharacterFrequencyScore(s string) float64 {
	count := make(map[rune]int)
	score := float64(0)
	letterCount := 0

	// need to keep track of these...
	lowerCount := 0

	// bump up the scores for some tuning
	// if it's not valid unicode, chances are it's not a plaintext
	if !utf8.Valid([]byte(s)) {
		score += 100
	}

	for _, r := range s {
		// and if it's not any of these, chances are it's not a plaintext
		if !unicode.IsLetter(rune(r)) &&
			!unicode.IsNumber(rune(r)) &&
			!unicode.IsPunct(rune(r)) &&
			!unicode.IsSpace(rune(r)) {
			score += 100
		}

		if unicode.IsLetter(rune(r)) {
			count[unicode.ToLower(rune(r))]++
			letterCount++
			// keep track of lowercase letters to distinguish between keys
			// that are offset by 32
			if unicode.IsLower(rune(r)) {
				lowerCount++
			} else {
				score += 10
			}
		}
	}

	// assume plaintexts will consist of at least 50% lowercase letters
	// and 75% upper/lowercase letters
	if float64(lowerCount)/float64(len(s)) < 0.5 && float64(letterCount)/float64(len(s)) < 0.75 {
		return math.Inf(1)
	}

	//chi-squared
	for i := range count {
		score += math.Pow((engFreq[i]*float64(letterCount))-float64(count[i]), 2) / (engFreq[i] * float64(letterCount))
	}

	return score
}

// IndexOfCoincidence measures the autocorrelation of a text. A higher IC
// suggests that the text is plaintext or encrypted with a single substitution
// cipher (rather than, say, a Vigenere cipher). This is used to detect key
// length in a Vigenere cipher since the subtext encrypted with each byte
// of the key will have a similar frequency distribution to the original text.
// The challenge says to use Hamming distance, but I was on a roll and not
// paying attention. Oh well, whatever works...
// Cryptopals Set 1, Challenge 6
// https://cryptopals.com/sets/1/challenges/6
func IndexOfCoincidence(s string) float64 {
	count := make(map[rune]int)

	for _, v := range s {
		count[rune(v)]++
	}

	score := float64(0)

	for _, v := range count {
		score += (float64(v*(v-1)) / float64(len(s)*(len(s)-1)))
	}

	return score
}
