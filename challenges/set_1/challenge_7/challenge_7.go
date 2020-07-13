// Driver program for Cryptopals Set 1, challenge 1
// https://cryptopals.com/sets/1/challenges/1
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/fileutils"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	key := "YELLOW SUBMARINE"
	keyBytes := []byte(key)

	ciphertextBytes, err := fileutils.BytesFromFile("./input.txt", base64.StdEncoding.DecodeString)
	check(err)

	decryptedBytes, err := ecb.Decrypt(ciphertextBytes, keyBytes)
	check(err)

	fmt.Println(string(decryptedBytes))
}
