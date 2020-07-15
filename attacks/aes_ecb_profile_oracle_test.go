package attacks

import (
	"testing"

	"github.com/adavidalbertson/cryptopals/aes/ecb"
	"github.com/adavidalbertson/cryptopals/random"
)

type randomOracle struct{}

func (pm randomOracle) ProfileFor(email string) (token []byte, err error) {
	return random.Bytes(4096), nil
}

func (pm randomOracle) DecryptProfile(ciphertext []byte) (profile ecb.UserProfile, err error) {
	return ecb.UserProfile{}, nil
}

func TestProfileOracleDetectBlockSize(t *testing.T) {
	type args struct {
		oracle profileMaker
	}
	tests := []struct {
		name          string
		args          args
		wantBlockSize int
		wantErr       bool
	}{
		{
			"challenge_13",
			args{ecb.NewProfileMaker()},
			16,
			false,
		},
		{
			"random_oracle",
			args{randomOracle{}},
			0,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBlockSize, err := ProfileOracleDetectBlockSize(tt.args.oracle)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProfileOracleDetectBlockSize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotBlockSize != tt.wantBlockSize {
				t.Errorf("ProfileOracleDetectBlockSize() = %v, want %v", gotBlockSize, tt.wantBlockSize)
			}
		})
	}
}

func TestProfileSpoofAdmin(t *testing.T) {
	type args struct {
		oracle profileMaker
	}
	tests := []struct {
		name     string
		args     args
		wantRole string
		wantErr  bool
	}{
		{
			"challenge_13",
			args{ecb.NewProfileMaker()},
			"admin",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCiphertext, err := ProfileSpoofAdmin(tt.args.oracle)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProfileSpoofAdmin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			decryptedProfile, err := tt.args.oracle.DecryptProfile(gotCiphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptProfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if decryptedProfile.GetRole() != tt.wantRole {
				t.Errorf("ProfileSpoofAdmin() = %v, want %v", decryptedProfile.GetRole(), tt.wantRole)
			}
		})
	}
}
