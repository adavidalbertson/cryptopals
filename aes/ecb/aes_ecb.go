package ecb

import (
	"crypto/aes"
)

// Encrypt bytes using AES in the ECB mode of operation.
// Force AES from the crypto package to run in ECB mode by working on one block at a time.
// This will be used as the basis for all the other AES modes of operation.
// Cryptopals Set 1, Challenge 7
// https://cryptopals.com/sets/1/challenges/7
func Encrypt(plaintextBytes, keyBytes []byte) (ciphertextBytes []byte, err error) {
	cipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return
	}

	blockSize := cipher.BlockSize()

	for len(plaintextBytes) > 0 {
		add := make([]byte, blockSize)
		cipher.Encrypt(add, plaintextBytes[:blockSize])
		plaintextBytes = plaintextBytes[blockSize:]
		ciphertextBytes = append(ciphertextBytes, add...)
	}

	return
}

// Decrypt bytes using AES in the ECB mode of operation.
// Force AES from the crypto package to run in ECB mode by working on one block at a time.
// This will be used as the basis for all the other AES modes of operation.
// Cryptopals Set 1, Challenge 7
// https://cryptopals.com/sets/1/challenges/7
func Decrypt(ciphertextBytes, keyBytes []byte) (plaintextBytes []byte, err error) {
	cipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return
	}

	blockSize := cipher.BlockSize()

	for len(ciphertextBytes) > 0 {
		add := make([]byte, blockSize)
		cipher.Decrypt(add, ciphertextBytes[:blockSize])
		ciphertextBytes = ciphertextBytes[blockSize:]
		plaintextBytes = append(plaintextBytes, add...)
	}

	return
}
