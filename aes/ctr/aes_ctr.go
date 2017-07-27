package ctr

import (
	"encoding/binary"
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/xor"
)

// AesCtrCipher stores the key, nonce, and counter for AES CTR encryption.
// Cryptopals Set 3, Challenge 18
// https://cryptopals.com/sets/3/challenges/18
type AesCtrCipher struct {
	key, nonce []byte
	counter    uint64
}

// NewAesCtrCipher sets initial values for key, nonce, and counter
// Cryptopals Set 3, Challenge 18
// https://cryptopals.com/sets/3/challenges/18
func NewAesCtrCipher(key, nonce []byte) (cipher AesCtrCipher, err error) {
	counter := uint64(0)
	if nonce == nil {
		nonce = make([]byte, 8)
	} else if len(nonce) != 8 {
		err = fmt.Errorf("Nonce has invalid length")
		return
	}

	if len(key) != 16 {
		err = fmt.Errorf("Key has invalid length")
		return
	}

	return AesCtrCipher{key, nonce, counter}, nil
}

// Encrypt the plaintext using the keystream generated by the cipher.
// Cryptopals Set 3, Challenge 18
// https://cryptopals.com/sets/3/challenges/18
func (cipher *AesCtrCipher) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	blockSize := 16
	var keystream []byte

	for i := 0; i <= len(plaintext); i += blockSize {
		counterBytes := make([]byte, 8)
		binary.PutUvarint(counterBytes, cipher.counter)
		next, err := ecb.Encrypt(append(cipher.nonce, counterBytes...), cipher.key)
		if err != nil {
			return ciphertext, err
		}

		keystream = append(keystream, next...)
		cipher.counter++
	}

	keystream = keystream[:len(plaintext)]
	ciphertext, err = xor.XOR(plaintext, keystream)

	return
}

// Decrypt is the same as encrypt (but must use a different cipher object!)
// Cryptopals Set 3, Challenge 18
// https://cryptopals.com/sets/3/challenges/18
func (cipher *AesCtrCipher) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	return cipher.Encrypt(ciphertext)
}

// Edit a ciphertext by seeking to the desired spot, initing a cipher with the
// appropriate counter value, and overwrite that portion of ciphertext with the
// encrypted newText. Replacement text starts at the beginning of a block.
// Cryptopals Set 4, Challenge 25
// https://cryptopals.com/sets/4/challenges/25
func (cipher *AesCtrCipher) Edit(ciphertext, newText []byte, offset int) (newCiphertext []byte, err error) {
	blockSize := 16
	if (offset * blockSize) >= len(ciphertext) {
		return ciphertext, fmt.Errorf("Offset (%d) exceeds ciphertext length (%d).", offset * blockSize, len(ciphertext))
	}

	tempCipher, err := NewAesCtrCipher(cipher.key, cipher.nonce)
	if err != nil {
		return
	}
	tempCipher.counter = uint64(offset)

	insert, err := tempCipher.Encrypt(newText)
	if err != nil {
		return
	}

	oldCiphertext := make([]byte, len(ciphertext))
	copy(oldCiphertext, ciphertext)

	newCiphertext = append(oldCiphertext[:offset * blockSize], insert...)
	if (offset * blockSize) + len(insert) < len(ciphertext) {
		newCiphertext = append(newCiphertext, ciphertext[(offset * blockSize) + len(insert):]...)
	}

	return newCiphertext, nil
}
