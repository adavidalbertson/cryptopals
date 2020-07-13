package attacks

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/adavidalbertson/cryptopals/xor"
)

func TestBreakSingleCharacterXorHex(t *testing.T) {
	type testCase struct {
		name          string
		ciphertext    string
		wantPlaintext string
		wantKey       byte
		wantErr       bool
	}

	newTestCase := func(name, plaintext string, key byte) (tc testCase) {
		tc.name = name
		tc.wantPlaintext = plaintext
		tc.wantKey = key

		tc.ciphertext = hex.EncodeToString(xor.VigenereXorBytes([]byte(plaintext), []byte{key}))

		return
	}

	testCases := []testCase{
		{
			"challenge_3",
			"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
			"Cooking MC's like a pound of bacon",
			0x58,
			false,
		},
		{
			"invalid_ciphertext",
			"abcdefg",
			"",
			0x00,
			true,
		},
		newTestCase("Spain", "The rain in Spain falls mainly on the plain", 0xAB),
		newTestCase("Axes", "Yo, this beat's old school like Acheulian hand axes", 0x42),
		newTestCase("Breakfast", "And I'm a yolk man, I like my eggs porous. Watch me get fat like a prego stegosaurus", 0xAD),
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			gotPlaintext, gotKey, gotScore, err := BreakSingleCharacterXorHex(tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("BreakSingleCharacterXorHex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPlaintext != tt.wantPlaintext {
				t.Errorf("BreakSingleCharacterXorHex() gotPlaintext = %v, want %v, score = %f", gotPlaintext, tt.wantPlaintext, gotScore)
			}
			if gotKey != tt.wantKey {
				t.Errorf("BreakSingleCharacterXorHex() gotKey = %v, want %v, score = %f", gotKey, tt.wantKey, gotScore)
			}
		})
	}
}

func TestBreakVigenereXor(t *testing.T) {
	type testCase struct {
		name          string
		ciphertext    []byte
		wantPlaintext string
		wantKey       []byte
	}

	newTestCase := func(name, key, plaintext string) (tc testCase) {
		tc.name = name
		tc.wantKey = []byte(key)
		tc.wantPlaintext = plaintext

		tc.ciphertext = xor.VigenereXorBytes([]byte(plaintext), tc.wantKey)

		return
	}

	tests := []testCase{
		newTestCase("Breakfast", "bfast", "I like to wake up early making bacon and eggs, yeah I'm out of coffee beans so I'm drinking the dregs. And I'm a yolk man, I like my eggs porous. Watch me get fatter than a preggo stegosaurus"),
		newTestCase("Time", "bunny", "Yo, this beat's old school like Acheulian hand axes, sound like we slipped a few xanaxes at band practice. We got the game plan encompassing all factors, we stay fly like a pair ot pterodactyls"),
		newTestCase("True", "posse", "I'm a Blackwater mercenary, money on my mind, my head's a secret cavern that no human can define. The last digit of pi, can't die, cause I defy all laws of physics, man, and nature that the rest of you live by"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPlaintext, gotKey := BreakVigenereXor(tt.ciphertext)
			if gotPlaintext != tt.wantPlaintext {
				t.Errorf("BreakVigenereXor() gotPlaintext = %v, want %v", gotPlaintext, tt.wantPlaintext)
			}
			if !reflect.DeepEqual(gotKey, tt.wantKey) {
				t.Errorf("BreakVigenereXor() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}

func TestDetectSingleCharacterXor(t *testing.T) {
	type args struct {
		ciphertexts [][]byte
	}
	type testCase struct {
		name string
		args args
		want KeyScore
	}

	newTestCaseFromFile := func(name, fname, ciphertext, plaintext string, key byte) (tc testCase) {

		ciphertexBytes, err := hex.DecodeString(ciphertext)
		if err != nil {
			panic(err)
		}

		tc.name = name
		tc.want.Ciphertext = ciphertexBytes
		tc.want.Plaintext = []byte(plaintext)
		tc.want.Key = key

		absPath, err := filepath.Abs(fname)
		if err != nil {
			panic(err)
		}

		file, err := os.Open(absPath)
		defer file.Close()
		if err != nil {
			panic(err)
		}

		read := bufio.NewScanner(file)

		ciphertexts := make([][]byte, 0)

		for read.Scan() {
			ciphertextHex, err := hex.DecodeString(read.Text())
			if err != nil {
				panic(err)
			}

			ciphertexts = append(ciphertexts, ciphertextHex)
		}

		tc.args.ciphertexts = ciphertexts

		return
	}

	tests := []testCase{
		newTestCaseFromFile("challenge_5", "../challenges/set_1/challenge_4/input.txt", "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f", "Now that the party is jumping", 0x35),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectSingleCharacterXor(tt.args.ciphertexts...); !reflect.DeepEqual(got.Ciphertext, tt.want.Ciphertext) {
				t.Errorf("DetectSingleCharacterXor() = %v, want %v", got, tt.want)
			}
		})
	}
}
