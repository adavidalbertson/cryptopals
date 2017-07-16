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
	oracle := cbc.NewAesCbcOracle()

	plaintext := "some data;admin=true"
	ciphertext, err := oracle.Encrypt(plaintext)
    check(err)

	success, err := oracle.Decrypt(ciphertext)
	check(err)

	if success {
		fmt.Println("Congratulations, you are admin!")
	} else {
		fmt.Println("Nope, try again")
	}

	fmt.Println()
	fmt.Println("=============================================================")
	fmt.Println()

	ciphertext, err = attacks.AesCbcOracleBreak(oracle)
    check(err)

	success, err = oracle.Decrypt(ciphertext)
	check(err)

	if success {
		fmt.Println("Congratulations, you are admin!")
	} else {
		fmt.Println("Nope, try again")
	}
}
