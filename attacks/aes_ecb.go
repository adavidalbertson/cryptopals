package attacks

import (
	"bytes"
	"fmt"

	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/padding"
)

// AesEcbDetect returns true if the input is likely to be a ciphertext encrypted in ECB mode.
// Cryptopals Set 1, Challenge 8
// https://cryptopals.com/sets/1/challenges/8
func AesEcbDetect(inBytes []byte, blockSize int) bool {
	matches := 0
	for len(inBytes) > 0 {
		matchingBlock := inBytes[:blockSize]
		inBytes = inBytes[blockSize:]
		for j := 0; j < len(inBytes); j += blockSize {
			if bytes.Equal(inBytes[j:j+blockSize], matchingBlock) {
				matches++
			}
		}
	}

	return matches > 0
}

// AesEcbOracleDetectBlockSize detects the blocksize of the cipher used in AesEcbOracle.
// Returns 0 if ECB is not detected
// Cryptopals Set 2, Challenge 12
// https://cryptopals.com/sets/2/challenges/12
func AesEcbOracleDetectBlockSize(oracle ecb.AesEcbOracle) (blockSize int, err error) {
	ct1, err := oracle.Encrypt(make([]byte, 0))
	if err != nil {
		return
	}

	for i := 0; i <= 2048; i++ {
		plaintext := bytes.Repeat([]byte("A"), i)
		ct2, err := oracle.Encrypt(plaintext)
		if err != nil {
			break
		}

		if len(ct2) > len(ct1) {
			return len(ct2) - len(ct1), nil
		}
	}

	return 0, fmt.Errorf("ECB mode not detected")
}

// getBlankBlock returns the ciphertext block corresponding to a zero plaintext.
func getBlankBlock(oracle ecb.AesEcbOracle, blockSize int) (blankBlock []byte, err error) {
	plaintext := make([]byte, 3*blockSize)
	ciphertext, err := oracle.Encrypt(plaintext)
	if err != nil {
		return
	}

	for i := 0; i < len(ciphertext)-2*blockSize; i += blockSize {
		if bytes.Equal(ciphertext[i:i+blockSize], ciphertext[i+blockSize:i+2*blockSize]) {
			return ciphertext[i : i+blockSize], err
		}
	}
	return make([]byte, blockSize), fmt.Errorf("Could not make blank block")
}

// AesEcbOracleBreak recovers unknown bytes from AesEcbOracle one byte at a time.
// Adapted to accommodate prefix for Challenge 14.
// Cryptopals Set 2, Challenge 14
// https://cryptopals.com/sets/2/challenges/14
func AesEcbOracleBreak(oracle ecb.AesEcbOracle) (plaintext []byte, err error) {
	blockSize, err := AesEcbOracleDetectBlockSize(oracle)
	if err != nil {
		return
	}

	blankBlock, err := getBlankBlock(oracle, blockSize)
	if err != nil {
		return
	}

	fill := 0
	startBlock := 0
	finishedLength := 0
	for i := 0; i < blockSize; i++ {
		ciphertext, err := oracle.Encrypt(make([]byte, blockSize+i))
		if err != nil {
			break
		}
		for j := 0; j <= len(ciphertext)-blockSize; j += blockSize {
			if bytes.Equal(ciphertext[j:j+blockSize], blankBlock) {
				fill, startBlock = i, j
				finishedLength = len(ciphertext) - blockSize - startBlock
				break
			}
		}
		if finishedLength > 0 {
			break
		}
	}
	if err != nil {
		return
	}

	var recovered []byte
	// Recover the i-th byte of the unknown suffix in oracle.
	for i := 0; i <= finishedLength; i++ {
		// Keep track of what block we're on.
		// We're recovering the (i % blockSize)-th byte of the block-th block.
		block := (i / blockSize)
		dummy := bytes.Repeat([]byte("A"), fill+blockSize-1-(i%blockSize))
		ciphertext, err := oracle.Encrypt(dummy)
		if err != nil {
			break
		}

		matchingBlock := ciphertext[block*blockSize+startBlock : (block+1)*blockSize+startBlock]

		for j := 0; j < 256; j++ {
			plaintext := append(dummy, recovered...)
			plaintext = append(plaintext, byte(j))
			dictEntry, err := oracle.Encrypt(plaintext)
			if err != nil {
				break
			}

			if bytes.Equal(matchingBlock, dictEntry[block*blockSize+startBlock:(block+1)*blockSize+startBlock]) {
				recovered = append(recovered, byte(j))
				break
			}
		}

		if len(recovered) >= finishedLength {
			return padding.Pkcs7Unpad(recovered)
		}
	}
	if err != nil {
		return
	}

	return padding.Pkcs7Unpad(recovered)
}
