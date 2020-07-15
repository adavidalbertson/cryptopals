package attacks

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/adavidalbertson/cryptopals/aes/ecb"
)

type profileMaker interface {
	ProfileFor(email string) (token []byte, err error)
	DecryptProfile(ciphertext []byte) (profile ecb.UserProfile, err error)
}

// ProfileOracleDetectBlockSize detects the block size of the cipher used to encrypt user tokens.
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
func ProfileOracleDetectBlockSize(oracle profileMaker) (blockSize int, err error) {
	ciphertext, err := oracle.ProfileFor(strings.Repeat("A", 2048))
	if err != nil {
		return
	}

	// assume no block shorter than 8 bytes
	for blockSize = 8; blockSize < len(ciphertext); blockSize++ {
		for j := 0; j < len(ciphertext)-2*blockSize; j += blockSize {
			if bytes.Equal(ciphertext[j:j+blockSize], ciphertext[j+blockSize:j+(2*blockSize)]) {
				return blockSize, err
			}
		}
	}

	return 0, fmt.Errorf("ECB mode not detected")

}

// ProfileSpoofAdmin creates a token with the role "admin".
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
func ProfileSpoofAdmin(oracle profileMaker) (ciphertext []byte, err error) {
	blockSize, err := ProfileOracleDetectBlockSize(oracle)
	if err != nil {
		return
	}

	adminBlock, err := makeFinalBlock(oracle, "admin", blockSize)
	if err != nil {
		return
	}

	ct1, err := oracle.ProfileFor("foo@bar.com")
	if err != nil {
		return
	}

	for i := 0; i <= blockSize; i++ {
		email := "foo@bar.com" + strings.Repeat(" ", i)
		ct2, err := oracle.ProfileFor(email)
		if err != nil {
			return ciphertext, err
		}
		if len(ct2) > len(ct1) {
			// the ciphertext gained a block, so the previous length was overflowed by one character
			email = "foo@bar.com" + strings.Repeat(" ", i+4)
			ct2, err = oracle.ProfileFor(email)
			if err != nil {
				return ciphertext, err
			}
			ciphertext = append(ct2[:len(ct2)-blockSize], adminBlock...)
			return ciphertext, err
		}
	}

	return make([]byte, 0), fmt.Errorf("Unable to generate admin user")
}

// makeFinalBlock creates a token block consisting of only the specified string.
// Cryptopals Set 2, Challenge 13
// https://cryptopals.com/sets/2/challenges/13
func makeFinalBlock(oracle profileMaker, param string, blockSize int) (finalBlock []byte, err error) {
	desiredBlock := param
	if len(desiredBlock)%blockSize != 0 {
		desiredBlock += strings.Repeat(" ", blockSize-(len(param)%blockSize))
	}

	for i := 0; i <= blockSize; i++ {
		offset := strings.Repeat("A", i)
		email := offset + desiredBlock + desiredBlock

		ciphertext, err := oracle.ProfileFor(email)
		if err != nil {
			return finalBlock, err
		}

		for j := 0; j < len(ciphertext)-(2*blockSize); j += blockSize {
			if bytes.Equal(ciphertext[j:j+blockSize], ciphertext[j+blockSize:j+(2*blockSize)]) {
				return ciphertext[j : j+blockSize], err
			}
		}
	}

	return make([]byte, 0), fmt.Errorf("Unable to find ciphertext block for \"%s\"", param)
}
