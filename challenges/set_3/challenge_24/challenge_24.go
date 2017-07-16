package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "github.com/adavidalbertson/cryptopals/attacks"
    "github.com/adavidalbertson/cryptopals/random"
    "github.com/adavidalbertson/cryptopals/random/MT19937"
    "time"
)

func main() {
    fmt.Println("Part 1: Verify that MT19937 CTR encryption/decryption works")

    key := binary.LittleEndian.Uint16(random.Bytes(2))
    fmt.Println("Initializing Mersenne Twister CTR with the key:", key)
    cipher := MT19937.NewCtrCipher(key)
    plaintext := make([]byte, 0)

    w := make([]byte, 4)
    binary.LittleEndian.PutUint32(w, 0xAAAAAAAA)
    for i := 0; i < 4; i++ {
        plaintext = append(plaintext, w...)
    }
    fmt.Println("plaintext:", plaintext)

    ciphertext := cipher.Encrypt(plaintext)
    fmt.Println("ciphertext:", ciphertext)

    decrypted := cipher.Decrypt(ciphertext)
    fmt.Println("decrypted:", decrypted)

    if !bytes.Equal(plaintext, decrypted) {
        panic("Encryption/decryption not working")
    }

    fmt.Println("Encryption/decryption definitely working")

    fmt.Println()
    fmt.Println("========================================")
    fmt.Println()

    fmt.Println("Part 2: Break MT19937 CTR oracle with known plaintext")

    oracle := MT19937.NewCtrOracle()
    key = attacks.BreakMT19937CtrOracle(oracle)

    fmt.Println("Found the key:", key)

    fmt.Println()
    fmt.Println("========================================")
    fmt.Println()

    fmt.Println("Part 3: Validate password reset token")

    before := time.Now().Unix()
    token := MT19937.PasswordResetToken()
    after := time.Now().Unix()

    seed := attacks.RecoverTimedSeed(before, after, token)

    fmt.Println("Recovered seed:", seed)
}
