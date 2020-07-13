package attacks

import (
	"encoding/hex"
	"math"
	"runtime"
	"sort"

	"github.com/adavidalbertson/cryptopals/xor"
)

// KeyScore represents an attempted break of a single character xor ciphertext, including
// said ciphertext, the suspected plaintext and key, and the frequency analysis score
type KeyScore struct {
	Ciphertext []byte
	Plaintext  []byte
	Key        byte
	Score      float64
}

type vigenereKeyFragment struct {
	index    int
	fragment byte
}

type vigenereCiphertextFragment struct {
	index    int
	fragment []byte
}

// BreakSingleCharacterXorHex is a wrapper for BreakSingleCharacterXor.
// Takes a hex string as input and returns the plaintext, key, and score.
// Cryptopals Set 1, Challenge 3
// https://cryptopals.com/sets/1/challenges/3
func BreakSingleCharacterXorHex(ciphertext string) (plaintext string, key byte, score float64, err error) {
	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return
	}

	plaintextBytes, key, score := BreakSingleCharacterXor(ciphertextBytes)
	plaintext = string(plaintextBytes)

	return
}

// BreakSingleCharacterXor uses frequency analysis to break XOR cipher.
// Cryptopals Set 1, Challenge 3
// https://cryptopals.com/sets/1/challenges/3
func BreakSingleCharacterXor(ciphertext []byte) (plaintext []byte, key byte, score float64) {
	best := breakSingleCharacterXorWrapped(ciphertext)

	return best.Plaintext, best.Key, best.Score
}

func breakSingleCharacterXorWrapped(ciphertext []byte) (ks KeyScore) {
	cores := runtime.NumCPU()
	chunkSize := 256 / cores
	keyScoreChan := make(chan KeyScore, cores)

	for i := 0; i < cores; i++ {
		go func(keyScoreChan chan KeyScore, i int) {
			best := KeyScore{Key: byte(0), Score: math.Inf(1)}
			for j := 0; j < chunkSize; j++ {
				key := byte(i*chunkSize + j)
				potentialPlaintext := xor.VigenereXorBytes(ciphertext, []byte{key})
				score := CharacterFrequencyScore(string(potentialPlaintext))

				if score < math.Inf(1) && math.Abs(score-best.Score) < .00001 {
					continue
				} else if score < best.Score {
					best = KeyScore{Key: key, Score: score, Plaintext: potentialPlaintext}
				}
			}

			keyScoreChan <- best
		}(keyScoreChan, i)
	}

	best := <-keyScoreChan
	for i := 1; i < cores; i++ {
		ks := <-keyScoreChan
		if ks.Score < math.Inf(1) && math.Abs(ks.Score-best.Score) < .00001 {
			continue
		} else if ks.Score < best.Score {
			best = ks
		}
	}

	return best
}

// DetectSingleCharacterXor accepts a range of potential ciphertexts and uses frequency analysis
// to pick the one most likely to be a ciphertext encrypted using single character xor
// Cryptopals Set 1, Challenge 4
// https://cryptopals.com/sets/1/challenges/4
func DetectSingleCharacterXor(ciphertexts ...[]byte) KeyScore {
	return singleCharacterXorScores(ciphertexts...)[0]
}

// DetectSingleCharacterXorTopN is a generalized version of DetectSingleCharacterXor that
// finds the n most likely ciphertexts
func DetectSingleCharacterXorTopN(n int, ciphertexts ...[]byte) []KeyScore {
	return singleCharacterXorScores(ciphertexts...)[:n]
}

// DetectSingleCharacterXorByThreshold is a generalized version of DetectSingleCharacterXor that
// finds the ciphertexts whose scores are below the given threshold
func DetectSingleCharacterXorByThreshold(threshold float64, ciphertexts ...[]byte) (scores []KeyScore) {
	candidates := singleCharacterXorScores(ciphertexts...)
	lastIndex := 0
	for i, candidate := range candidates {
		if candidate.Score > threshold {
			lastIndex = i
			break
		}
	}

	return candidates[:lastIndex]
}

func singleCharacterXorScores(ciphertexts ...[]byte) (scores []KeyScore) {
	for _, ciphertext := range ciphertexts {
		plaintext, key, score := BreakSingleCharacterXor(ciphertext)
		scores = append(scores, KeyScore{ciphertext, plaintext, key, score})
	}

	sort.Slice(scores, func(i, j int) bool { return scores[i].Score < scores[j].Score })

	return scores
}

// BreakVigenereXor uses frequency analysis to break Vigenere XOR cipher.
// Cryptopals Set 1, Challenge 6
// https://cryptopals.com/sets/1/challenges/6
func BreakVigenereXor(ciphertextBytes []byte) (plaintext string, key []byte) {
	keyLength := vigenereXorKeyLength(ciphertextBytes)
	subSeqs := unzip(ciphertextBytes, keyLength)
	keyBytes := make([]byte, keyLength)

	textPieces := make(chan vigenereCiphertextFragment, keyLength)
	keyPieces := make(chan vigenereKeyFragment, keyLength)

	numWorkers := runtime.NumCPU()

	for i := 0; i < numWorkers; i++ {
		go func(textPieces chan vigenereCiphertextFragment, keyPieces chan vigenereKeyFragment) {
			for textPiece := range textPieces {
				_, key, _ := BreakSingleCharacterXor(textPiece.fragment)
				keyPieces <- vigenereKeyFragment{textPiece.index, key}
			}
		}(textPieces, keyPieces)
	}

	for i, subSeq := range subSeqs {
		textPieces <- vigenereCiphertextFragment{i, subSeq}
	}

	close(textPieces)

	for i := 0; i < keyLength; i++ {
		keyPiece := <-keyPieces
		keyBytes[keyPiece.index] = keyPiece.fragment
	}

	plaintextBytes := xor.VigenereXorBytes(ciphertextBytes, keyBytes)

	return string(plaintextBytes), keyBytes
}

// vigenereXorKeyLength detects the likely length of the key used in encryption.
func vigenereXorKeyLength(ciphertextBytes []byte) (bestLength int) {
	bestScore := float64(0)
	bestLength = 1

	// Assume key length less then 1/4 of ciphertext length
	for potentialLength := 1; potentialLength < len(ciphertextBytes)/4; potentialLength++ {
		subSeqs := unzip(ciphertextBytes, potentialLength)

		// indices of coincidence
		ICs := make([]float64, potentialLength)
		for i, subSeq := range subSeqs {
			ICs[i] = float64(IndexOfCoincidence(string(subSeq)))
		}

		avgIC := float64(0)
		for _, IC := range ICs {
			avgIC += IC / float64(potentialLength)
		}

		if avgIC > bestScore && (bestLength == 1 || potentialLength%bestLength != 0) {
			bestScore = avgIC
			bestLength = potentialLength
		}
	}

	return bestLength
}

// unzip separates a byte slice into n byte slices consisting of every nth byte.
func unzip(byteSlice []byte, numSubSeqs int) (subSeqs [][]byte) {
	subSeqs = make([][]byte, numSubSeqs)
	subSeqLength := (len(byteSlice) / numSubSeqs) + 1
	for i := range subSeqs {
		subSeqs[i] = make([]byte, 0, subSeqLength)
	}

	subSeqIndex := 0
	for _, b := range byteSlice {
		subSeqs[subSeqIndex] = append(subSeqs[subSeqIndex], b)

		subSeqIndex = (subSeqIndex + 1) % numSubSeqs
	}

	return subSeqs
}
