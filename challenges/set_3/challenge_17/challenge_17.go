package main

import (
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes/cbc"
	"github.com/adavidalbertson/cryptopals/attacks"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	oracle := cbc.NewPaddingOracle()

	plaintext, err := attacks.PaddingOracleAttack(oracle)
	check(err)

	fmt.Println(plaintext)
	fmt.Println(string(plaintext))
}
