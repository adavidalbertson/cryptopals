package fileutils

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestByteSlicesFromFile(t *testing.T) {
	type args struct {
		fname  string
		decode func(line string) ([]byte, error)
	}
	tests := []struct {
		name           string
		args           args
		wantByteSlices [][]byte
		wantErr        bool
	}{
		{
			"hex",
			args{"./testCaseHex.txt", hex.DecodeString},
			[][]byte{
				{0x01, 0x23, 0x45, 0x67},
				{0x89, 0xAB, 0xCD, 0xEF},
				{0xDE, 0xAD, 0xBE, 0xEF},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotByteSlices, err := ByteSlicesFromFile(tt.args.fname, tt.args.decode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ByteSlicesFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotByteSlices, tt.wantByteSlices) {
				t.Errorf("ByteSlicesFromFile() = %v, want %v", gotByteSlices, tt.wantByteSlices)
			}
		})
	}
}

func TestBytesFromFile(t *testing.T) {
	type args struct {
		fname  string
		decode func(line string) (bytes []byte, err error)
	}
	tests := []struct {
		name      string
		args      args
		wantBytes []byte
		wantErr   bool
	}{
		{
			"hex",
			args{"./testCaseHex.txt", hex.DecodeString},
			[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, err := BytesFromFile(tt.args.fname, tt.args.decode)
			if (err != nil) != tt.wantErr {
				t.Errorf("BytesFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBytes, tt.wantBytes) {
				t.Errorf("BytesFromFile() = %v, want %v", gotBytes, tt.wantBytes)
			}
		})
	}
}
