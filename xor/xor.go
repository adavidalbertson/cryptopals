package xor

import (
	"encoding/hex"
	"errors"
)

// FixedXor takes two hex strings and produces their XOR'ed output.
// Cryptopals Set 1, Challenge 2
// https://cryptopals.com/sets/1/challenges/2
// operates on hex strings, not very useful
func FixedXor(a, b string) (hexResult string, hexError error) {
	aBytes, hexError := hex.DecodeString(a)
	if hexError != nil {
		return
	}

	bBytes, hexError := hex.DecodeString(b)
	if hexError != nil {
		return
	}

	aBytes, bBytes = matchByteSliceLengths(aBytes, bBytes)

	outBytes := make([]byte, len(aBytes))

	for i := range outBytes {
		outBytes[i] = aBytes[i] ^ bBytes[i]
	}

	hexResult = hex.EncodeToString(outBytes)

	return
}

func matchByteSliceLengths(a, b []byte) ([]byte, []byte) {
	if len(a) == len(b) {
		return a, b
	}

	swap := len(a) < len(b)

	if swap {
		b, a = a, b
	}

	padding := make([]byte, len(a)-len(b))
	b = append(padding, b...)

	if swap {
		b, a = a, b
	}

	return a, b
}

// VigenereXorEncrypt encrypts plaintext using the key.
// Wrapper function for VigenereXorBytes that accepts arbitrary strings for the inputs
// and returns the result as a hex encoded string
// Cryptopals Set 1, Challenge 5
// https://cryptopals.com/sets/1/challenges/5
func VigenereXorEncrypt(plaintext, key string) string {
	plaintextBytes := []byte(plaintext)
	keyBytes := []byte(key)

	return hex.EncodeToString(VigenereXorBytes(plaintextBytes, keyBytes))
}

// VigenereXorDecrypt decrypts ciphertext using the key.
// Wrapper function for VigenereXorBytes that accepts a hex encoded string for the ciphertext
// and an arbitrary string for the key, and returns the plaitext as a string
// Cryptopals Set 1, Challenge 5
// https://cryptopals.com/sets/1/challenges/5
func VigenereXorDecrypt(ciphertext, key string) (plaintext string, hexError error) {
	ciphertextBytes, hexError := hex.DecodeString(ciphertext)
	if hexError != nil {
		return
	}
	keyBytes := []byte(key)

	return string(VigenereXorBytes(ciphertextBytes, keyBytes)), hexError
}

// VigenereXorBytes applies the Vigenere cipher to byte slices.
// Same for encryption and decryption.
// Cryptopals Set 1, Challenge 5
// https://cryptopals.com/sets/1/challenges/5
func VigenereXorBytes(bytesIn, key []byte) (bytesOut []byte) {
	bytesOut = make([]byte, len(bytesIn))
	keyIndex := 0

	for i := range bytesIn {
		bytesOut[i] = bytesIn[i] ^ key[keyIndex]
		keyIndex = (keyIndex + 1) % len(key)
	}

	return bytesOut
}

// Xor produces the Xor'ed output of two byte slices.
// utility function for Cryptopals Set 2, Challenge 10
// https://cryptopals.com/sets/2/challenges/10
func Xor(a, b []byte) (outBytes []byte, err error) {
	if len(a) != len(b) {
		err = errors.New("XOR inputs are not the same length")
		a, b = matchByteSliceLengths(a, b)
	}

	outBytes = make([]byte, len(a))

	for i := range outBytes {
		outBytes[i] = a[i] ^ b[i]
	}

	return outBytes, err
}
