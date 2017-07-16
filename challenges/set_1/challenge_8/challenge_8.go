// Driver program for Cryptopals Set 1, challenge 8
// https://cryptopals.com/sets/1/challenges/8
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/adavidalbertson/cryptopals/attacks"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	lineIndex := 0
	line := ""
	blockSize := 16

	file, err := os.Open("input.txt")
	check(err)

	defer file.Close()

	read := bufio.NewScanner(file)
	for read.Scan() {
		lineIndex++
		line = read.Text()
		lineBytes, err := hex.DecodeString(line)
		check(err)

		ecbDetected := attacks.AesEcbDetect(lineBytes, blockSize)
		if ecbDetected {
			fmt.Println("ECB detected!", lineIndex, line)
		}
	}
}
