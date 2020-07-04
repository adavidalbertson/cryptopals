// Driver program for Cryptopals Set 1, challenge 2
// https://cryptopals.com/sets/1/challenges/2
package main

import (
	"fmt"
	"github.com/adavidalbertson/cryptopals/xor"
)

func main() {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"

	c, err := xor.FixedXor(a, b)
	if err != nil {
		panic(err)
	}

	expectedOutput := "746865206b696420646f6e277420706c6179"

	fmt.Println(c)
	fmt.Println(c == expectedOutput)
}
