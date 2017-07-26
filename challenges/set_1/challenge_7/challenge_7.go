// Driver program for Cryptopals Set 1, challenge 1
// https://cryptopals.com/sets/1/challenges/1
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	key := "YELLOW SUBMARINE"
	keyBytes := []byte(key)

	file, err := os.Open("input.txt")
	check(err)

	defer file.Close()

	read := bufio.NewScanner(file)
	ciphertextBytes := make([]byte, 1)
	for read.Scan() {
		line := read.Text()
		lineBytes, err := base64.StdEncoding.DecodeString(line)
		check(err)

		ciphertextBytes = append(ciphertextBytes, lineBytes...)
	}

	//first byte needs trimmed off for some reason
	ciphertextBytes = ciphertextBytes[1:]

	decryptedBytes, err := ecb.Decrypt(ciphertextBytes, keyBytes)
	check(err)

	fmt.Println(string(decryptedBytes))
}
