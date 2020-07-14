package padding

import (
	"bytes"
	"fmt"
)

// Pkcs7 pads messages to match a given blockSize according to RF 2315.
// https://tools.ietf.org/html/rfc2315#section-10.3
// Cryptopals Set 1, Challenge 9
// https://cryptopals.com/sets/1/challenges/9
func Pkcs7(partial []byte, blockSize int) (padded []byte, err error) {
	padded = partial

	if blockSize >= 256 {
		err = fmt.Errorf("Block size must be less than 256 bytes (https://tools.ietf.org/html/rfc2315#section-10.3)")
		return
	}

	p := blockSize - (len(padded) % blockSize)
	for i := 0; i < p; i++ {
		padded = append(padded, byte(p))
	}

	return
}

// Pkcs7Unpad removes padding from message.
// Returns an error if the padding is invalid.
// Cryptopals Set 1, Challenge 9
// https://cryptopals.com/sets/1/challenges/9
func Pkcs7Unpad(padded []byte) (unpadded []byte, err error) {
	p := padded[len(padded)-1]

	unpadded = bytes.TrimRight(padded, string(p))

	if len(padded)-len(unpadded) != int(p) {
		return make([]byte, 0), fmt.Errorf("Invalid padding: %s", string(padded))
	}

	return
}
