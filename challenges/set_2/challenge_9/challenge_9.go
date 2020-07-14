package main

import (
	"fmt"

	"github.com/adavidalbertson/cryptopals/padding"
)

func main() {
	blockSize := 20
	partial := []byte("YELLOW SUBMARINE")

	complete, err := padding.Pkcs7(partial, blockSize)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%q\n", complete)
}
