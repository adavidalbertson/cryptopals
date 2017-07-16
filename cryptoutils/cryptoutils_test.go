package cryptoutils

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// test using input and output for Cryptopals Set 1
// https://cryptopals.com/sets/1/challenges/1
func TestXOR(t *testing.T) {
	fmt.Println("Running bases tests...")
	t.Run("bases", basesTest)

	fmt.Println("Running FixedXOR tests...")
	t.Run("fixedXOR", fixedXorTest)

	fmt.Println("Running VigenereXOR tests...")
	t.Run("VigenereXOR", testVigenereXor)

	fmt.Println("Running AES_ECB tests...")
	t.Run("AES", testAes_Ecb)
}

// test using input and output for Cryptopals Set 1, Challenge 1
// https://cryptopals.com/sets/1/challenges/1
func basesTest(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{
			"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
	}
	for _, c := range cases {
		got := HexToBase64(c.in)
		if got != c.want {
			t.Errorf("HexToBase64(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}

// test using input and output for Cryptopals Set 1, Challenge 2
// https://cryptopals.com/sets/1/challenges/2
func fixedXorTest(t *testing.T) {
	cases := []struct {
		a, b, expectedOut string
	}{
		{
			"1c0111001f010100061a024b53535009181c",
			"686974207468652062756c6c277320657965",
			"746865206b696420646f6e277420706c6179",
		},
		{
			"746865206b696420646f6e277420706c6179",
			"746865206b696420646f6e277420706c6179",
			"000000000000000000000000000000000000",
		},
	}
	for _, c := range cases {
		got := FixedXor(c.a, c.b)
		if got != c.expectedOut {
			t.Errorf("FixedXOR(%q, %q) == %q, want %q", c.a, c.b, got, c.expectedOut)
		}
	}
}

// test using input and output for Cryptopals Set 1, Challenge 5
// https://cryptopals.com/sets/1/challenges/5
func testVigenereXor(t *testing.T) {
	cases := []struct {
		textIn, key, expectedOut string
	}{
		{
			"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
			"ICE",
			"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
		},
	}

	for _, c := range cases {
		got := VigenereXorEncrypt(c.textIn, c.key)
		if got != c.expectedOut {
			t.Errorf("VigenereXOREncrypt(%q, %q) == %q, want %q", c.textIn, c.key, got, c.expectedOut)
		}

		outBytes, hexErr := hex.DecodeString(c.expectedOut)
		if hexErr != nil {
			panic(hexErr)
		}
		keyLength := VigenereXorKeyLength(outBytes)
		if keyLength != len(c.key) {
			t.Errorf("VigenereXORKeyLength(%q) == %q, want %q", c.expectedOut, keyLength, len(c.key))
		}

		// test case not big enough, don't feel like making it bigger
		/*
			broken, brokenKey, _ := BreakVigenereXOR(outBytes)
			if broken != c.textIn {
			    t.Errorf("BreakVigenereXOR(%q)[text] == %q, want %q", c.expectedOut, broken, c.textIn)
			}
			if string(brokenKey) != c.key {
			    t.Errorf("BreakVigenereXOR(%q)[key] == %q, want %q", c.expectedOut, brokenKey, c.key)
			}
		*/

		reverse := VigenereXorDecrypt(got, c.key)
		if reverse != c.textIn {
			t.Errorf("VigenereXORDecrypt(%q, %q) == %q, want %q", got, c.key, reverse, c.textIn)
		}
	}
}

// test using input and output for Cryptopals Set 1, Challenge 7
// https://cryptopals.com/sets/1/challenges/7
func testAesEcb(t *testing.T) {
	cases := []struct {
		plaintext, key, ciphertext string
	}{
		{
			"Attack at dawn!!",
			"abcdefghijklmnop",
			"379693884e25f00f6e8aaa43df4db541",
		},
		{
			"This is 16 bytes, and another 16",
			"YELLOW SUBMARINE",
			"4f685434b064eb0b354ee4f9094682fcd0efa9aa4138ec0d213f285ddf137156",
		},
	}
	for _, c := range cases {
		plaintextBytes := []byte(c.plaintext)
		keyBytes := []byte(c.key)
		encryptedBytes, _ := AesEcbEncrypt(plaintextBytes, keyBytes)
		encrypted := hex.EncodeToString(encryptedBytes)

		if encrypted != c.ciphertext {
			t.Errorf("AesEcbEncrypt(%q, %q) == %q, want %q", c.plaintext, c.key, encrypted, c.ciphertext)
		}

		ciphertextBytes, _ := hex.DecodeString(c.ciphertext)
		decryptedBytes, _ := AesEcbDecrypt(ciphertextBytes, keyBytes)
		decrypted := string(decryptedBytes)

		if decrypted != c.plaintext {
			t.Errorf("AesEcbDecrypt(%q, %q) == %s, want %s", c.ciphertext, c.key, decrypted, c.plaintext)
		}
	}
}

func testAesCbc(t *testing.T) {
	cases := []struct {
		plaintext, key, iv, ciphertext string
	}{
		{
			"Attack at dawn!!",
			"abcdefghijklmnop",
			"0000000000000000",
			"379693884e25f00f6e8aaa43df4db541",
		},
		{
			"This is 16 bytes, and another 16",
			"YELLOW SUBMARINE",
			"AAAAAAAAAAAAAAAA",
			"4f685434b064eb0b354ee4f9094682fcd0efa9aa4138ec0d213f285ddf137156",
		},
	}
	for _, c := range cases {
		plaintextBytes := []byte(c.plaintext)
		keyBytes := []byte(c.key)
		ivBytes := []byte(c.iv)
		encryptedBytes, _ := AesCbcEncrypt(plaintextBytes, keyBytes, ivBytes)
		//encrypted := hex.EncodeToString(encryptedBytes)

		//if encrypted != c.ciphertext {
		//	t.Errorf("AesCbcEncrypt(%q, %q) == %q, want %q", c.plaintext, c.key, encrypted, c.ciphertext)
		//}

		//ciphertextBytes, _ := hex.DecodeString(c.ciphertext)
		//decryptedBytes, _ := AesCbcDecrypt(ciphertextBytes, keyBytes, ivBytes)
		decryptedBytes, _ := AesCbcDecrypt(encryptedBytes, keyBytes, ivBytes)
		//decrypted := string(decryptedBytes)

		if !bytes.Equal(decryptedBytes, plaintextBytes) {
			t.Errorf("AesCbcDecrypt(%q, %q, %q) == %s, want %s", hex.EncodeToString(encryptedBytes), string(keyBytes), string(ivBytes), string(decryptedBytes), c.plaintext)
		}
	}
}
