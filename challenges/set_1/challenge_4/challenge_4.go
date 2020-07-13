// Driver program for Cryptopals Set 1, challenge 4
// https://cryptopals.com/sets/1/challenges/4
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/adavidalbertson/cryptopals/attacks"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	file, err := os.Open("input.txt")
	defer file.Close()
	check(err)

	read := bufio.NewScanner(file)

	ciphertexts := make([][]byte, 0)

	for read.Scan() {
		ciphertextHex, err := hex.DecodeString(read.Text())
		check(err)

		ciphertexts = append(ciphertexts, ciphertextHex)
	}

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
