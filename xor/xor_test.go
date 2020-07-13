package xor

import (
	"reflect"
	"testing"
)

func TestFixedXor(t *testing.T) {
	type args struct {
		a string
		b string
	}
	tests := []struct {
		name          string
		args          args
		wantHexResult string
		wantErr       bool
	}{
		{
			"challenge_2",
			args{"1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"},
			"746865206b696420646f6e277420706c6179",
			false,
		},
		{
			"invalid_a",
			args{"abcdeg", "abcdef"},
			"",
			true,
		},
		{
			"invalid_b",
			args{"abcdef", "abcdeg"},
			"",
			true,
		},
		{
			"odd_length",
			args{"abcde", "edcba"},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHexResult, err := FixedXor(tt.args.a, tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("FixedXor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHexResult != tt.wantHexResult {
				t.Errorf("FixedXor() = %v, want %v", gotHexResult, tt.wantHexResult)
			}
		})
	}
}

func Test_matchByteSliceLengths(t *testing.T) {
	type args struct {
		a []byte
		b []byte
	}
	tests := []struct {
		name        string
		args        args
		wantAPadded []byte
		wantBPadded []byte
	}{
		{
			"equal",
			args{[]byte{0x01, 0x02, 0x03}, []byte{0x0A, 0x0B, 0x0C}},
			[]byte{0x01, 0x02, 0x03},
			[]byte{0x0A, 0x0B, 0x0C},
		},
		{
			"a_long",
			args{[]byte{0x01, 0x02, 0x03, 0x04, 0x05}, []byte{0x0A, 0x0B, 0x0C}},
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05},
			[]byte{0x00, 0x00, 0x0A, 0x0B, 0x0C},
		},
		{
			"b_long",
			args{[]byte{0x01, 0x02, 0x03}, []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E}},
			[]byte{0x00, 0x00, 0x01, 0x02, 0x03},
			[]byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAPadded, gotBPadded := matchByteSliceLengths(tt.args.a, tt.args.b)
			if !reflect.DeepEqual(gotAPadded, tt.wantAPadded) {
				t.Errorf("matchByteSliceLengths() gotAPadded = %v, want %v", gotAPadded, tt.wantAPadded)
			}
			if !reflect.DeepEqual(gotBPadded, tt.wantBPadded) {
				t.Errorf("matchByteSliceLengths() gotBPadded = %v, want %v", gotBPadded, tt.wantBPadded)
			}
		})
	}
}

func TestXor(t *testing.T) {
	type args struct {
		a []byte
		b []byte
	}
	tests := []struct {
		name         string
		args         args
		wantOutBytes []byte
		wantErr      bool
	}{
		{
			"happy_path",
			args{[]byte{0x01, 0x02}, []byte{0x0A, 0x0B}},
			[]byte{0x0B, 0x09},
			false,
		},
		{
			"mismatch",
			args{[]byte{0x01, 0x02}, []byte{0x0A, 0x0B, 0x0C}},
			[]byte{0x0A, 0x0A, 0x0E},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOutBytes, err := Xor(tt.args.a, tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("Xor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOutBytes, tt.wantOutBytes) {
				t.Errorf("Xor() = %v, want %v", gotOutBytes, tt.wantOutBytes)
			}
		})
	}
}

func TestVigenereXorBytes(t *testing.T) {
	type args struct {
		bytesIn []byte
		key     []byte
	}
	tests := []struct {
		name         string
		args         args
		wantBytesOut []byte
	}{
		{
			"happy_path",
			args{[]byte{0x67, 0x89, 0xAB, 0xCD, 0xEF}, []byte{0x21, 0x43}},
			[]byte{0x46, 0xCA, 0x8A, 0x8E, 0xCE},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotBytesOut := VigenereXorBytes(tt.args.bytesIn, tt.args.key); !reflect.DeepEqual(gotBytesOut, tt.wantBytesOut) {
				t.Errorf("VigenereXorBytes() = %v, want %v", gotBytesOut, tt.wantBytesOut)
			}
		})
	}
}

func TestVigenereXorEncrypt(t *testing.T) {
	type args struct {
		plaintext string
		key       string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"challenge_5",
			args{"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"},
			"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VigenereXorEncrypt(tt.args.plaintext, tt.args.key); got != tt.want {
				t.Errorf("VigenereXorEncrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVigenereXorDecrypt(t *testing.T) {
	type args struct {
		ciphertext string
		key        string
	}
	tests := []struct {
		name          string
		args          args
		wantPlaintext string
		wantErr       bool
	}{
		{
			"challenge_5",
			args{"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", "ICE"},
			"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
			false,
		},
		{
			"invalid_ciphertext",
			args{"abcdefg", "key"},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPlaintext, err := VigenereXorDecrypt(tt.args.ciphertext, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("VigenereXorDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPlaintext != tt.wantPlaintext {
				t.Errorf("VigenereXorDecrypt() = %v, want %v", gotPlaintext, tt.wantPlaintext)
			}
		})
	}
}
