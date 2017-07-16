// Driver program for Cryptopals Set 1, challenge 3
// https://cryptopals.com/sets/1/challenges/3
package main

import (
	"fmt"
	"github.com/adavidalbertson/cryptopals/attacks"
)

func main() {
	ciphertext := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	plaintext, key, score, err := attacks.BreakSingleCharacterXORHex(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
	fmt.Println(key, score)
}
