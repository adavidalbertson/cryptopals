// Driver program for Cryptopals Set 4, challenge 25
// https://cryptopals.com/sets/1/challenges/1
package main

import (
    "bufio"
    "fmt"
    "github.com/adavidalbertson/cryptopals/aes/ctr"
    "github.com/adavidalbertson/cryptopals/attacks"
    "github.com/adavidalbertson/cryptopals/random"
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

	defer file.Close()

	read := bufio.NewScanner(file)
	plaintextBytes := make([]byte, 1)
	for read.Scan() {
		lineBytes := []byte(read.Text() + "\n")

		plaintextBytes = append(plaintextBytes, lineBytes...)
	}

    key := random.Bytes(16)
    nonce := random.Bytes(8)
    cipher, err := ctr.NewAesCtrCipher(key, nonce)
    check(err)
    ciphertextBytes, err := cipher.Encrypt(plaintextBytes)
    check(err)

    newCiphertext, err := cipher.Edit(ciphertextBytes, []byte("Bork"), 1)
    check(err)

    fmt.Println(ciphertextBytes[:32])
    fmt.Println(newCiphertext[:32])

    fmt.Println("=============================================================")

    recovered, err := attacks.BreakCtrEdit(cipher, ciphertextBytes)
    check(err)

    fmt.Println(string(recovered))
}
