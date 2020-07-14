package padding

import (
	"reflect"
	"testing"
)

func TestPkcs7(t *testing.T) {
	type args struct {
		partial   []byte
		blockSize int
	}
	tests := []struct {
		name       string
		args       args
		wantPadded []byte
		wantErr    bool
	}{
		{"challenge_9", args{[]byte("YELLOW SUBMARINE"), 20}, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), false},
		{"empty", args{[]byte{}, 8}, []byte{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}, false},
		{"block_size_too_large", args{[]byte("YELLOW SUBMARINE"), 512}, []byte("YELLOW SUBMARINE"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPadded, err := Pkcs7(tt.args.partial, tt.args.blockSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("Pkcs7() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPadded, tt.wantPadded) {
				t.Errorf("Pkcs7() = %v, want %v", gotPadded, tt.wantPadded)
			}
		})
	}
}

func TestPkcs7Unpad(t *testing.T) {
	type args struct {
		padded []byte
	}
	tests := []struct {
		name         string
		args         args
		wantUnpadded []byte
		wantErr      bool
	}{
		{"challenge_15_valid", args{[]byte("ICE ICE BABY\x04\x04\x04\x04")}, []byte("ICE ICE BABY"), false},
		{"challenge_15_invalid_1", args{[]byte("ICE ICE BABY\x05\x05\x05\x05")}, []byte{}, true},
		{"challenge_15_invalid_2", args{[]byte("ICE ICE BABY\x01\x02\x03\x04")}, []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUnpadded, err := Pkcs7Unpad(tt.args.padded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Pkcs7Unpad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUnpadded, tt.wantUnpadded) {
				t.Errorf("Pkcs7Unpad() = %v, want %v", gotUnpadded, tt.wantUnpadded)
			}
		})
	}
}
