package attacks

import (
	"github.com/adavidalbertson/cryptopals/aes/cbc"
	"github.com/adavidalbertson/cryptopals/padding"
	"github.com/adavidalbertson/cryptopals/xor"
	// "net/url"
	"strings"
)

// AesCbcOracleBreak creates a user token with admin parameter set to true.
// Cryptopals Set 2, Challenge 16
// https://cryptopals.com/sets/2/challenges/16
func AesCbcOracleBreak(oracle cbc.AesCbcOracle) (token []byte, err error) {
	blockSize := 16
	// luckily the prefix is exactly two blocks long
	empty := strings.Repeat("0", blockSize+5)
	plaintext := ";admin=true"
	plaintext, altered := flipChars(empty + plaintext)

	plaintext = empty + ":;admin<=true"
	token, err = oracle.Encrypt(plaintext)
	if err != nil {
		return make([]byte, 0), err
	}

	for _, v := range altered {
		token[blockSize+v] = token[blockSize+v] ^ byte(1)
	}

	return
}

func flipChars(in string) (s string, indices []int) {
	s = in
	for {
		i := strings.IndexAny(s, ";=")
		if i == -1 {
			return
		}

		indices = append(indices, i)
		s = strings.Join([]string{s[:i], string(byte(s[i]) ^ byte(1)), s[i+1:]}, "")
	}
}

// PaddingOracleAttack determines the oracle's plaintext.
// Cryptopals Set 3, Challenge 17
// https://cryptopals.com/sets/3/challenges/17
func PaddingOracleAttack(oracle cbc.PaddingOracle) ([]byte, error) {
	blockSize := 16
	ciphertext, iv := oracle.Encrypt()
	plaintext := make([]byte, len(ciphertext))

	var left []byte
	alteredBlock := make([]byte, blockSize)
	trialBlock := make([]byte, blockSize)

	for block := -blockSize; block < len(ciphertext)-blockSize; block += blockSize {
		for i := blockSize - 1; i >= 0; i-- {
			paddingByte := byte(blockSize - i)
			if block < 0 {
				copy(alteredBlock, iv)
			} else {
				copy(left, ciphertext[:block])
				copy(alteredBlock, ciphertext[block:block+blockSize])
			}

			pad := make([]byte, blockSize)
			for j := i; j < blockSize; j++ {
				pad[j] = paddingByte
			}

			alteredBlock, err := xor.XOR(alteredBlock, pad)
			if err != nil {
				return nil, err
			}
			alteredBlock, err = xor.XOR(alteredBlock, plaintext[block+blockSize:block+2*blockSize])
			if err != nil {
				return nil, err
			}

			for k := 0; k < 256; k++ {
				if block < 0 {
					trialIV := make([]byte, blockSize)
					copy(trialIV, alteredBlock)
					trialIV[i] = trialIV[i] ^ byte(k)
					if oracle.Validate(ciphertext[block+blockSize:block+2*blockSize], trialIV) {
						plaintext[block+blockSize+i] = byte(k)
						break
					}
				} else {
					copy(trialBlock, alteredBlock)
					trialBlock[i] = trialBlock[i] ^ byte(k)

					trialCiphertext := append(left, trialBlock...)
					trialCiphertext = append(trialCiphertext, ciphertext[block+blockSize:block+2*blockSize]...)
					if oracle.Validate(trialCiphertext, iv) {
						plaintext[block+blockSize+i] = byte(k)
						// can't break here because ciphertext block may contain padding
					}
				}
			}
		}
	}
	plaintext, _ = padding.Pkcs7Unpad(plaintext)
	return plaintext, nil
}
