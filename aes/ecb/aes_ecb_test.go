package ecb

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/adavidalbertson/cryptopals/fileutils"
)

type args struct {
	input    []byte
	keyBytes []byte
}
type testCase struct {
	name       string
	args       args
	wantOutput []byte
	wantErr    bool
}

func newTestCaseFromFiles(name, inputPath, outputPath, key string, wantErr bool) (tc testCase) {
	var err error
	tc.name = name
	tc.args.input, err = fileutils.BytesFromFile(inputPath, base64.StdEncoding.DecodeString)
	if err != nil {
		panic(err)
	}

	tc.args.keyBytes = []byte(key)
	tc.wantOutput, err = fileutils.BytesFromFile(outputPath, base64.StdEncoding.DecodeString)
	if err != nil {
		panic(err)
	}

	tc.wantErr = wantErr

	return
}

func TestDecrypt(t *testing.T) {
	tests := []testCase{
		newTestCaseFromFiles("challenge_7",
			"../../challenges/set_1/challenge_7/input.txt",
			"../../challenges/set_1/challenge_7/output_base64.txt",
			"YELLOW SUBMARINE",
			false,
		),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPlaintextBytes, err := Decrypt(tt.args.input, tt.args.keyBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPlaintextBytes, tt.wantOutput) {
				t.Errorf("Decrypt() = %v, want %v", gotPlaintextBytes, tt.wantOutput)
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	tests := []testCase{
		newTestCaseFromFiles("challenge_7",
			"../../challenges/set_1/challenge_7/output_base64.txt",
			"../../challenges/set_1/challenge_7/input.txt",
			"YELLOW SUBMARINE",
			false,
		),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCiphertextBytes, err := Encrypt(tt.args.input, tt.args.keyBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCiphertextBytes, tt.wantOutput) {
				t.Errorf("Encrypt() = %v, want %v", gotCiphertextBytes, tt.wantOutput)
			}
		})
	}
}
