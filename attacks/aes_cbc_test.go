package attacks

import (
	"testing"

	"github.com/adavidalbertson/cryptopals/aes/cbc"
)

func TestAesCbcOracleBreak(t *testing.T) {
	t.Run("challenge_16", func(t *testing.T) {
		oracle := cbc.NewAesCbcOracle()

		gotToken, err := AesCbcOracleBreak(oracle)
		isAdmin, err := oracle.Decrypt(gotToken)

		if err != nil {
			t.Errorf("AesCbcOracleBreak() error = %v", err)
			return
		}

		if !isAdmin {
			t.Errorf("NewAesCbcOracle.Decrypt(AesCbcOracleBreak()) = %v, want %v", gotToken, false)
		}
	})
}
