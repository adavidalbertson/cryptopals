package main

import (
	"bufio"
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes"
	"github.com/adavidalbertson/cryptopals/attacks"
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
		line := read.Text()
		plaintextBytes = append(plaintextBytes, []byte(line)...)
	}

	ciphertextBytes, err := aes.Oracle(plaintextBytes)
	check(err)

	ecbDetected := attacks.AesEcbDetect(ciphertextBytes, 16)

	if ecbDetected {
		fmt.Println("Detected ECB")
	} else {
		fmt.Println("Did not detect ECB")
	}
}
