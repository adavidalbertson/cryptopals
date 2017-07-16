package attacks

import (
	"encoding/hex"
	"github.com/adavidalbertson/cryptopals/xor"
	"math"
	"runtime"
)

type keyScore struct {
	key   byte
	score float64
	text  []byte
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
	cores := runtime.NumCPU()
	chunkSize := 256 / cores
	keyScoreChan := make(chan keyScore, cores)

	for i := 0; i < cores; i++ {
		go func(keyScoreChan chan keyScore, i int) {
			best := keyScore{key: byte(0), score: math.Inf(1)}
			for j := 0; j < chunkSize; j++ {
				key := byte(i*chunkSize + j)
				potentialPlaintext := xor.VigenereXorBytes(ciphertext, []byte{key})
				score := CharacterFrequencyScore(string(potentialPlaintext))

				if score < math.Inf(1) && math.Abs(score-best.score) < .00001 {
					continue
				} else if score < best.score {
					best = keyScore{key, score, potentialPlaintext}
				}
			}

			keyScoreChan <- best
		}(keyScoreChan, i)
	}

	best := <-keyScoreChan
	for i := 1; i < cores; i++ {
		ks := <-keyScoreChan
		if ks.score < math.Inf(1) && math.Abs(ks.score-best.score) < .00001 {
			continue
		} else if ks.score < best.score {
			best = ks
		}
	}

	return best.text, best.key, best.score
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
