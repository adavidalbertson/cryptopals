package ecb

import (
	crand "crypto/rand"
	mrand "math/rand"
	"time"

	"github.com/adavidalbertson/cryptopals/padding"
	"github.com/adavidalbertson/cryptopals/random"
)

// EncryptionOracle is an interface containing only an Encrypt function
type EncryptionOracle interface {
	Encrypt([]byte) []byte
}

// AesEcbOracle contains an unknown key, optional prefix, and suffix for encryption.
type AesEcbOracle struct {
	prefix, suffix, key []byte
}

// NewAesEcbOracle returns a new AesEcbOracle that uses the specified suffix,
// a random key, and if desired, a random prefix (for Challenge 14).
// Cryptopals Set 2, Challenge 12
// https://cryptopals.com/sets/2/challenges/12
func NewAesEcbOracle(suffix []byte, addPrefix bool) (AesEcbOracle, error) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	key := make([]byte, 16)

	var prefix []byte
	if addPrefix {
		// prepend 5-10 random bytes
		prefix = random.Bytes(5 + r.Intn(6))
	}

	_, err := crand.Read(key)
	return AesEcbOracle{prefix, suffix, key}, err
}

// Encrypt appends the oracle's prefix (if any) and suffix to the plaintext.
// It then encrypts the result using the oracle's key.
func (oracle AesEcbOracle) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	plaintext = append(oracle.prefix, plaintext...)
	plaintext = append(plaintext, oracle.suffix...)
	plaintext, err = padding.Pkcs7(plaintext, 16)
	if err != nil {
		return
	}

	return Encrypt(plaintext, oracle.key)
}
