package aes

import (
	"fmt"
	mrand "math/rand"
	"time"

	"github.com/adavidalbertson/cryptopals/aes/cbc"
	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/padding"
	"github.com/adavidalbertson/cryptopals/random"
)

// type EncryptionOracle interface {
// 	Encrypt() []byte
// }

// type AesOracle struct {
// 	plaintext []byte
// 	key []byte
// }

// Oracle takes a plaintext, adds a random prefix and suffix, then encrypts
// it using either ECB or CBC mode at random, using a random 16-byte key.
// For testing, it prints the mode used.
// Cryptopals Set 2, Challenge 11
// https://cryptopals.com/sets/2/challenges/11
func Oracle(plaintext []byte) (ciphertext []byte, err error) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	key := random.Bytes(16)
	plaintext = append(random.Bytes(5+r.Intn(6)), plaintext...)
	plaintext = append(plaintext, random.Bytes(5+r.Intn(6))...)
	plaintext, err = padding.Pkcs7(plaintext, 16)
	if err != nil {
		return
	}

	switch mode := r.Intn(2); mode {
	case 0:
		ciphertext, err = ecb.Encrypt(plaintext, key)
		fmt.Println("Used ECB...")
		break
	case 1:
		ciphertext, err = cbc.Encrypt(plaintext, key, random.Bytes(16))
		fmt.Println("Used CBC...")
		break
	}

	return
}
