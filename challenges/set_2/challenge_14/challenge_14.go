package main

import (
	"encoding/base64"
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/attacks"
	"os"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	unknownBytes, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	check(err)

	oracle, err := ecb.NewAesEcbOracle(unknownBytes, true)
	check(err)

	blockSize, err := attacks.AesEcbOracleDetectBlockSize(oracle)
	check(err)

	if blockSize > 0 {
		fmt.Println("Block size:", blockSize)
	} else {
		fmt.Println("ECB mode not detected")
		os.Exit(0)
	}

	recovered, err := attacks.AesEcbOracleBreak(oracle)
	check(err)

	fmt.Println("Recovered:", string(recovered))
}
