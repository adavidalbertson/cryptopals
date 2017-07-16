// Driver program for Cryptopals Set 1, challenge 6
// https://cryptopals.com/sets/1/challenges/6
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/adavidalbertson/cryptopals/attacks"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	file, err := os.Open("input.txt")
	check(err)

	read := bufio.NewScanner(file)

	ciphertextBytes := make([]byte, 1)

	for read.Scan() {
		line := read.Text()
		lineBytes, err := base64.StdEncoding.DecodeString(line)
		check(err)

		ciphertextBytes = append(ciphertextBytes, lineBytes...)
	}

	decrypted, _ := attacks.BreakVigenereXor(ciphertextBytes);

	fmt.Println(decrypted);
}
