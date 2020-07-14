package main

import (
	"encoding/base64"
	"fmt"

	"github.com/adavidalbertson/cryptopals/aes/cbc"
	"github.com/adavidalbertson/cryptopals/fileutils"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	key := []byte("YELLOW SUBMARINE")

	ciphertext, err := fileutils.BytesFromFile("input.txt", base64.StdEncoding.DecodeString)
	check(err)

	decrypted, err := cbc.Decrypt(ciphertext, key, nil)
	check(err)
	fmt.Println(string(decrypted))
}
