package main

import (
	"fmt"

	"github.com/adavidalbertson/cryptopals/aes"
	"github.com/adavidalbertson/cryptopals/attacks"
	"github.com/adavidalbertson/cryptopals/fileutils"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	plaintextBytes, err := fileutils.BytesFromFile("input.txt", fileutils.Identity)

	ciphertextBytes, err := aes.Oracle(plaintextBytes)
	check(err)

	ecbDetected := attacks.AesEcbDetect(ciphertextBytes, 16)

	if ecbDetected {
		fmt.Println("Detected ECB")
	} else {
		fmt.Println("Did not detect ECB")
	}
}
