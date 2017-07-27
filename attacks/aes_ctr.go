package attacks

import (
    "fmt"
    "github.com/adavidalbertson/cryptopals/aes/ctr"
    "github.com/adavidalbertson/cryptopals/xor"
)

// BreakCtrEdit breaks CTR encryption by editing a string of zeros into the
// ciphertext. This reveals the keyStream.
// Cryptopals Set 4, Challenge 25
// https://cryptopals.com/sets/4/challenges/25
func BreakCtrEdit(cipher ctr.AesCtrCipher, ciphertext []byte) (plaintext []byte, err error) {
    plaintext = make([]byte, 0)
    fullBlockSize := 16
    for i := 0; i < len(ciphertext); i += fullBlockSize {
        blockSize := fullBlockSize
        if i + blockSize >= len(ciphertext) {
            blockSize = len(ciphertext) % blockSize
        }

        insertBlock := make([]byte, blockSize);
        edited, err := cipher.Edit(ciphertext, insertBlock, i/fullBlockSize)
        if err != nil {
            fmt.Println(err)
            return make([]byte, 0), err
        }

        editedBlock := edited[i : i + blockSize]
        ciphertextBlock := ciphertext[i : i + blockSize]

        plaintextBlock, err := xor.XOR(ciphertextBlock, editedBlock)
        if err != nil {
            return make([]byte, 0), err
        }

        plaintext = append(plaintext, plaintextBlock...)
    }
    return
}
