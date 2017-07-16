// Driver program for Cryptopals Set 1, challenge 4
// https://cryptopals.com/sets/1/challenges/4
package main

import (
	"bufio"
	"fmt"
	"github.com/adavidalbertson/cryptopals/attacks"
	"math"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	file, err := os.Open("input.txt")
	defer file.Close()
	check(err)

	read := bufio.NewScanner(file)

	bestCiphertextLine := ""
	bestLine := ""
	bestKey := byte(0)
	bestScore := math.Inf(1)

	for read.Scan() {
		ciphertextLine := read.Text()
		lineBroken, key, score, err := attacks.BreakSingleCharacterXorHex(ciphertextLine)
		check(err)

		if score < bestScore {
			bestCiphertextLine = ciphertextLine
			bestLine = lineBroken
			bestKey = key
			bestScore = score
		}
	}

	fmt.Println(bestCiphertextLine)
	fmt.Println(bestLine)
	fmt.Println(bestKey, bestScore)
}
