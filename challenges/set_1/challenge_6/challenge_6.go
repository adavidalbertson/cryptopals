// Driver program for Cryptopals Set 1, challenge 6
// https://cryptopals.com/sets/1/challenges/6
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/adavidalbertson/cryptopals/attacks"
	"github.com/adavidalbertson/cryptopals/fileutils"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	ciphertextBytes, err := fileutils.BytesFromFile("./input.txt", base64.StdEncoding.DecodeString)
	check(err)

	decrypted, key := attacks.BreakVigenereXor(ciphertextBytes)

	fmt.Println(decrypted)
	fmt.Println("============================================")
	fmt.Println(string(key))
}
