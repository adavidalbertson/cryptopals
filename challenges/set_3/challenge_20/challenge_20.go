package main

import (
    "bufio"
    "encoding/base64"
    "fmt"
    "github.com/adavidalbertson/cryptopals/aes/ctr"
    "github.com/adavidalbertson/cryptopals/attacks"
    "github.com/adavidalbertson/cryptopals/random"
    "github.com/adavidalbertson/cryptopals/xor"
    "os"
)

func check(err error) {
    if err != nil {
        panic(err)
    }
}

// Accidentally did it this way for Challenge 19, repeat for 20
func main() {
    f, err := os.Open("input.txt")
    defer f.Close()
    check(err)

    s := bufio.NewScanner(f)
    plaintexts := make([][]byte, 0)

    for s.Scan() {
        line, _ := base64.StdEncoding.DecodeString(s.Text())
        plaintexts = append(plaintexts, line)
    }

    ciphertexts := make([][]byte, len(plaintexts))
    key := random.Bytes(16)
    for i, plaintext := range(plaintexts) {
        cipher, _ := ctr.NewAesCtrCipher(key, nil)
        ciphertexts[i], err = cipher.Encrypt(plaintext)
        check(err)
    }

    maxLength := len(ciphertexts[26]) //happens to be the longest

    b := make([][]byte, maxLength)
    for _, ciphertext := range(ciphertexts) {
        for j, _ := range(ciphertext) {
            b[j] = append(b[j], ciphertext[j])
        }
    }

    keyStream := make([]byte, maxLength)
    for i, _ := range(b) {
        _, keyStream[i], _ = attacks.BreakSingleCharacterXor(b[i])
    }

    for _, c := range(ciphertexts) {
        decrypted := make([]byte, 0)
        if len(c) < maxLength {
            decrypted, _ = xor.XOR(c, keyStream[:len(c)])
        } else {
            decrypted, _ = xor.XOR(c, keyStream)
        }
        fmt.Println(string(decrypted))
    }
}
