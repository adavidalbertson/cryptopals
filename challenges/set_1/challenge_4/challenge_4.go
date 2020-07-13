// Driver program for Cryptopals Set 1, challenge 4
// https://cryptopals.com/sets/1/challenges/4
package main

import (
	"encoding/hex"
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
	ciphertexts, err := fileutils.ByteSlicesFromFile("./input.txt", hex.DecodeString)
	check(err)

	results := attacks.DetectSingleCharacterXorByThreshold(100, ciphertexts...)

	for i := range results {
		ciphertextLine := hex.EncodeToString(results[i].Ciphertext)
		line := string(results[i].Plaintext)
		key := results[i].Key
		score := results[i].Score

		fmt.Println(ciphertextLine)
		fmt.Println(line)
		fmt.Println(key, score)
		fmt.Println()
	}
}
