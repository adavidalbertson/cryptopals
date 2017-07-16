package main

import (
	"encoding/base64"
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes/ctr"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	decrypter, err := ctr.NewAesCtrCipher([]byte("YELLOW SUBMARINE"), nil)
	check(err)

	ciphertext, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	check(err)

	decrypted, err := decrypter.Decrypt(ciphertext)
	check(err)

	fmt.Println(decrypted)
	fmt.Println(string(decrypted))
}
