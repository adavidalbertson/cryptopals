// Driver program for Cryptopals Set 1, challenge 1
// https://cryptopals.com/sets/1/challenges/1
package main

import (
	"fmt"

	"github.com/adavidalbertson/cryptopals/cryptoutils"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	hexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	base64String, err := cryptoutils.HexToBase64(hexString)
	check(err)

	expectedOutput := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	fmt.Println(base64String)
	fmt.Println(base64String == expectedOutput)
}
