package cbc

import (
	"crypto/aes"
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/xor"
)

// Encrypt encrypts bytes using AES in the CBC mode of operation.
// Uses the ECB mode implemented for Set 1.
// Cryptopals Set 2, Challenge 10
// https://cryptopals.com/sets/2/challenges/10
func Encrypt(plaintextBytes, keyBytes, iv []byte) (ciphertextBytes []byte, err error) {
	cipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return
	}

	blockSize := cipher.BlockSize()
	if iv == nil {
		iv = make([]byte, blockSize)
	}

	if len(iv) != blockSize {
		err = fmt.Errorf("Initialization Vector not equal to block length")
	}
	if len(plaintextBytes)%blockSize != 0 {
		err = fmt.Errorf("len(plaintextBytes) == %d\nNeed a multiple of %d", len(plaintextBytes), blockSize)
	}

	ciphertextBytes = make([]byte, len(plaintextBytes))
	curBlock := iv
	for len(plaintextBytes) > 0 {
		diff, err := xor.Xor(plaintextBytes[:blockSize], curBlock)
		if err != nil {
			return make([]byte, 0), err
		}

		curBlock, err = ecb.Encrypt(diff, keyBytes)
		plaintextBytes = plaintextBytes[blockSize:]
		ciphertextBytes = append(ciphertextBytes, curBlock...)
	}

	// per openssl, padding is always added, so strip it off
	ciphertextBytes = ciphertextBytes[len(ciphertextBytes)/2:]

	return ciphertextBytes, err
}

// Decrypt decrypts bytes using AES in the CBC mode of operation.
// Cryptopals Set 2, Challenge 10
// https://cryptopals.com/sets/2/challenges/10
func Decrypt(ciphertextBytes, keyBytes, iv []byte) (plaintextBytes []byte, err error) {
	cipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return
	}

	blockSize := cipher.BlockSize()
	if iv == nil {
		iv = make([]byte, blockSize)
	}
	if len(iv) > blockSize {
		err = fmt.Errorf("Initialization Vector is longer than block length")
	}
	if len(ciphertextBytes)%blockSize != 0 {
		err = fmt.Errorf("len(ciphertextBytes) == %d\nNeed a multiple of %d", len(ciphertextBytes), blockSize)
	}

	plaintextBytes = make([]byte, len(ciphertextBytes))
	prevBlock := iv
	for len(ciphertextBytes) > 0 {
		curBlock, err := ecb.Decrypt(ciphertextBytes[:blockSize], keyBytes)
		if err != nil {
			return make([]byte, 0), err
		}

		curBlock, err = xor.Xor(curBlock, prevBlock)
		if err != nil {
			return make([]byte, 0), err
		}

		prevBlock = ciphertextBytes[:blockSize]
		ciphertextBytes = ciphertextBytes[blockSize:]
		plaintextBytes = append(plaintextBytes, curBlock...)
	}

	plaintextBytes = plaintextBytes[len(plaintextBytes)/2:]

	return plaintextBytes, err
}
