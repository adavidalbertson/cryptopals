package cryptoutils

import (
	"testing"
)

func TestHexToBase64(t *testing.T) {
	tests := []struct {
		name             string
		hexString        string
		wantBase64String string
		wantErr          bool
	}{
		{
			"challenge_1",
			"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
			false,
		},
		{
			"invalidHexString",
			"abcdefg",
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBase64String, err := HexToBase64(tt.hexString)
			if (err != nil) != tt.wantErr {
				t.Errorf("HexToBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotBase64String != tt.wantBase64String {
				t.Errorf("HexToBase64() = %v, want %v", gotBase64String, tt.wantBase64String)
			}
		})
	}
}
