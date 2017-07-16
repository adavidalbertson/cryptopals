package cbc

import (
	"fmt"
	"github.com/adavidalbertson/cryptopals/padding"
	"github.com/adavidalbertson/cryptopals/random"
	// "net/url"
	"strings"
)

// AesCbcOracle contains a prefix, suffix, key, and iv for encryption.
// Cryptopals Set 2, Challenge 16
// https://cryptopals.com/sets/2/challenges/16
type AesCbcOracle struct {
	prefix, suffix string
	iv, key        []byte
}

// NewAesCbcOracle sets a hardcoded prefix and suffix, and a random key and iv.
// Cryptopals Set 2, Challenge 16
// https://cryptopals.com/sets/2/challenges/16
func NewAesCbcOracle() AesCbcOracle {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	key := random.Bytes(16)
	iv := random.Bytes(16)

	return AesCbcOracle{prefix, suffix, key, iv}
}

// Encrypt strips ';' and '=', appends the oracle's prefix and suffix to the
// plaintext, pads, and encrypts with the oracle's key and iv.
// Cryptopals Set 2, Challenge 16
// https://cryptopals.com/sets/2/challenges/16
func (oracle AesCbcOracle) Encrypt(plaintext string) (token []byte, err error) {
	plaintext = strings.Replace(plaintext, ";", "", -1)
	plaintext = strings.Replace(plaintext, "=", "", -1)
	// plaintext = url.QueryEscape(plaintext)
	fmt.Println(plaintext)

	plaintext = oracle.prefix + plaintext + oracle.suffix
	plaintextBytes := padding.Pkcs7([]byte(plaintext), 16)

	ciphertext, err := Encrypt(plaintextBytes, oracle.key, oracle.iv)

	return ciphertext, err
}

// Decrypt takes an encrypted user token, and returns true if the admin parameter is true.
// Cryptopals Set 2, Challenge 16
// https://cryptopals.com/sets/2/challenges/16
func (oracle AesCbcOracle) Decrypt(ciphertext []byte) (isAdmin bool, err error) {
	plaintextBytes, err := Decrypt(ciphertext, oracle.key, oracle.iv)
	if err != nil {
		return
	}

	plaintextBytes, err = padding.Pkcs7Unpad(plaintextBytes)
	if err != nil {
		return
	}

	pairs := strings.Split(string(plaintextBytes), ";")
	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		if len(p) != 2 {
			err = fmt.Errorf("Invalid key-value pair: %s", pair)
			return
		}

		// p[0], _ = url.QueryUnescape(p[0])
		// p[1], _ = url.QueryUnescape(p[1])
		fmt.Printf("%s:\t%s\n", p[0], p[1])

		if p[0] == "admin" && p[1] == "true" {
			isAdmin = true
			return
		}
	}

	return
}
