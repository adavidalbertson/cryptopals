package main

import (
	"fmt"
	"github.com/adavidalbertson/cryptopals/padding"
)

func main() {
	blockSize := 20
	partial := []byte("YELLOW SUBMARINE")

	complete := padding.Pkcs7(partial, blockSize)

	fmt.Printf("%q\n", complete)
}
