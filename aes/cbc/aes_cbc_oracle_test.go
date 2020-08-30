package cbc

import (
	"testing"
)

func TestAesCbcOracle_Encrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		wantAdmin bool
		wantErr   bool
	}{
		{"challenge_16_hack_attempt", "some data;admin=true", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oracle := NewAesCbcOracle()
			gotCiphertext, err := oracle.Encrypt(tt.plaintext)

			gotAdmin, err := oracle.Decrypt(gotCiphertext)

			if (err != nil) != tt.wantErr {
				t.Errorf("AesCbcOracle.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAdmin != tt.wantAdmin {
				t.Errorf("AesCbcOracle.GetIsAdmin() = %v, want %v", gotAdmin, tt.wantAdmin)
			}
		})
	}
}
