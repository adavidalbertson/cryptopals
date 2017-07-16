package padding

import (
	"bytes"
	"fmt"
)

// Pkcs7 pads messages to match a given blockSize according to RF 2315.
// https://tools.ietf.org/html/rfc2315
// Cryptopals Set 1, Challenge 9
// https://cryptopals.com/sets/1/challenges/9
func Pkcs7(partial []byte, blockSize int) []byte {
	p := blockSize - (len(partial) % blockSize)
	for i := 0; i < p; i++ {
		partial = append(partial, byte(p))
	}

	return partial
}

// Pkcs7Unpad removes padding from message.
// Returns an error if the padding is invalid.
// Cryptopals Set 1, Challenge 9
// https://cryptopals.com/sets/1/challenges/9
func Pkcs7Unpad(padded []byte) (unpadded []byte, err error) {
	p := padded[len(padded)-1]

	if int(p) > 16 || int(p) == 0 {
		err = fmt.Errorf("No padding present")
		return
	}

	unpadded = bytes.TrimRight(padded, string(p))

	if len(padded)-len(unpadded) != int(p) {
		return make([]byte, 0), fmt.Errorf("Invalid padding: %s", string(padded))
	}

	return
}
