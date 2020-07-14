package main

import (
	"fmt"

	"github.com/adavidalbertson/cryptopals/padding"
)

func check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	padded, err := padding.Pkcs7([]byte("YELLOW SUB"), 16)
	check(err)
	unpadded, err := padding.Pkcs7Unpad(padded)
	check(err)

	fmt.Println(padded, string(unpadded))

	fmt.Println()
	fmt.Println("=============================================================")
	fmt.Println()

	padded = []byte("YELLOW SUB\x03\x03\x03\x03\x03\x03")
	unpadded, err = padding.Pkcs7Unpad(padded)
	check(err)

	fmt.Println(padded, string(unpadded))
}
