// Driver program for Cryptopals Set 1, challenge 5
// https://cryptopals.com/sets/1/challenges/5

package main

import (
	"fmt"
	"github.com/adavidalbertson/cryptopals/xor"
)

func main() {
	plaintext := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"

	ciphertext := xor.VigenereXorEncrypt(plaintext, key)
	expectedCiphertext := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	fmt.Println(ciphertext)
	fmt.Println(ciphertext == expectedCiphertext)
}
