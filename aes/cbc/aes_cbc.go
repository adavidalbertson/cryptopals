package cbc

import (
	"fmt"

	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/xor"
)

func getAndValidateBlockSize(input, key, iv []byte) (blockSize int, err error) {
	blockSize = len(key)
	if blockSize != 16 && blockSize != 24 && blockSize != 32 {
		err = fmt.Errorf("key has length %d, which is not a valid block size for AES", blockSize)
		return
	}

	if iv != nil && len(iv) != blockSize {
		err = fmt.Errorf("Initialization Vector not equal to block length")
		return
	}
	if len(input)%blockSize != 0 {
		err = fmt.Errorf("len(plaintextBytes) == %d\nNeed a multiple of %d", len(input), blockSize)
		return
	}

	return
}

// Encrypt encrypts bytes using AES in the CBC mode of operation.
// Uses the ECB mode implemented for Set 1.
// Cryptopals Set 2, Challenge 10
// https://cryptopals.com/sets/2/challenges/10
func Encrypt(plaintext, key, iv []byte) (ciphertext []byte, err error) {
	blockSize, err := getAndValidateBlockSize(plaintext, key, iv)
	if err != nil {
		return
	}

	if iv == nil {
		iv = make([]byte, blockSize)
	}

	ciphertext = make([]byte, len(plaintext))
	curBlock := iv
	for len(plaintext) > 0 {
		diff, err := xor.Xor(plaintext[:blockSize], curBlock)
		if err != nil {
			return make([]byte, 0), err
		}

		curBlock, err = ecb.Encrypt(diff, key)
		plaintext = plaintext[blockSize:]
		ciphertext = append(ciphertext, curBlock...)
	}

	// per openssl, padding is always added, so strip it off
	ciphertext = ciphertext[len(ciphertext)/2:]

	return ciphertext, err
}

// Decrypt decrypts bytes using AES in the CBC mode of operation.
// Cryptopals Set 2, Challenge 10
// https://cryptopals.com/sets/2/challenges/10
func Decrypt(ciphertext, key, iv []byte) (plaintext []byte, err error) {
	blockSize, err := getAndValidateBlockSize(ciphertext, key, iv)
	if err != nil {
		return
	}

	if iv == nil {
		iv = make([]byte, blockSize)
	}

	plaintext = make([]byte, len(ciphertext))
	prevBlock := iv
	for len(ciphertext) > 0 {
		curBlock, err := ecb.Decrypt(ciphertext[:blockSize], key)
		if err != nil {
			return make([]byte, 0), err
		}

		curBlock, err = xor.Xor(curBlock, prevBlock)
		if err != nil {
			return make([]byte, 0), err
		}

		prevBlock = ciphertext[:blockSize]
		ciphertext = ciphertext[blockSize:]
		plaintext = append(plaintext, curBlock...)
	}

	plaintext = plaintext[len(plaintext)/2:]

	return plaintext, err
}
