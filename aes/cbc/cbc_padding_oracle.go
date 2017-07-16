package cbc

import (
	"encoding/base64"
	// "fmt"
	"github.com/adavidalbertson/cryptopals/padding"
	"github.com/adavidalbertson/cryptopals/random"
	mrand "math/rand"
	"time"
)

// PaddingOracle holds a randomly selected plaintext, key, and iv.
// Cryptopals Set 3, Challenge 17
// https://cryptopals.com/sets/3/challenges/17
type PaddingOracle struct {
	plaintext, key, iv []byte
}

// NewPaddingOracle randomly selects a plaintext, and generates a key and iv.
// Cryptopals Set 3, Challenge 17
// https://cryptopals.com/sets/3/challenges/17
func NewPaddingOracle() PaddingOracle {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	key := random.Bytes(16)
	iv := random.Bytes(16)

	plaintexts := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	plaintextIndex := r.Intn(len(plaintexts))

	plaintext, _ := base64.StdEncoding.DecodeString(plaintexts[plaintextIndex])
	// fmt.Println(plaintext)
	// fmt.Println(string(plaintext))

	return PaddingOracle{plaintext, key, iv}
}

// Encrypt encrypts the oracle's plaintext with its key and iv.
// Returns the ciphertext and iv.
// Cryptopals Set 3, Challenge 17
// https://cryptopals.com/sets/3/challenges/17
func (oracle PaddingOracle) Encrypt() (ciphertext, iv []byte) {
	ciphertext, _ = Encrypt(padding.Pkcs7(oracle.plaintext, 16), oracle.key, oracle.iv)

	return ciphertext, oracle.iv
}

// Validate returns true if the plaintext was correctly padded.
// Cryptopals Set 3, Challenge 17
// https://cryptopals.com/sets/3/challenges/17
func (oracle PaddingOracle) Validate(ciphertext, iv []byte) bool {
	decrypted, _ := Decrypt(ciphertext, oracle.key, iv)
	decrypted, err := padding.Pkcs7Unpad(decrypted)

	if err == nil {
		return true
	}

	return false
}
