package random

import (
	crand "crypto/rand"
	mrand "math/rand"
	"time"
)

// Bytes generates a random byteslice of the desired length.
func Bytes(num int) []byte {
	out := make([]byte, num)
	_, _ = crand.Read(out)

	return out
}

// Prefix appends a random prefix of 5-10 bytes to a byteslice.
func Prefix(plaintext []byte) []byte {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	plaintext = append(Bytes(5+r.Intn(6)), plaintext...)

	return plaintext
}

// Suffix appends a random suffix of 5-10 bytes to a byteslice.
func Suffix(plaintext []byte) []byte {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	plaintext = append(plaintext, Bytes(5+r.Intn(6))...)

	return plaintext
}

// Surround appends a random prefix and suffix, each of 5-10 bytes, to a byteslice.
func Surround(plaintext []byte) []byte {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	plaintext = append(Bytes(5+r.Intn(6)), plaintext...)
	plaintext = append(plaintext, Bytes(5+r.Intn(6))...)

	return plaintext
}
