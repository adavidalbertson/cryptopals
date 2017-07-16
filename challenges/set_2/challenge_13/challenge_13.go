package main

import (
	"fmt"
	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/attacks"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	pm := ecb.NewProfileMaker()

    email := "foo@bar.com&role=admin"
	encryptedProfile, err := pm.ProfileFor(email)
	check(err)

    fmt.Println(email)

	decrypedProfile, err := pm.DecryptProfile(encryptedProfile)
	check(err)
	fmt.Println(decrypedProfile, "<-- Not that easy")

    fmt.Println()
    fmt.Println("=============================================================")
    fmt.Println()

    blockSize, err := attacks.ProfileOracleDetectBlockSize(pm)
    check(err)

    fmt.Println("Block size:", blockSize)

    adminCiphertext, err := attacks.ProfileSpoofAdmin(pm)
    check(err)

    adminProfile, err := pm.DecryptProfile(adminCiphertext)
    check(err)

    fmt.Println(adminProfile)
}
