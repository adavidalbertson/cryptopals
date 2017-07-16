package cryptoutils

import (
	"encoding/base64"
	"encoding/hex"
)

// HexToBase64 converts hex string to base 64 string.
// utility function for Cryptopals Set 1, Challenge 1
// https://cryptopals.com/sets/1/challenges/1
func HexToBase64(hexString string) (base64String string, hexError error) {
	rawBytes, hexError := hex.DecodeString(hexString)

	if hexError != nil {
		return
	}

	base64String = base64.StdEncoding.EncodeToString(rawBytes)

	return
}
