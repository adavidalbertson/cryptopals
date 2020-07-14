package attacks

import (
	"encoding/base64"
	"testing"
)

func TestAesEcbDetect(t *testing.T) {
	type args struct {
		inBytes   []byte
		blockSize int
	}
	type testCase struct {
		name string
		args args
		want bool
	}

	newTestCase := func(name, input string, want bool) (tc testCase) {
		var err error
		tc.name = name
		tc.args.inBytes, err = base64.StdEncoding.DecodeString(input)
		if err != nil {
			panic(err)
		}

		tc.args.blockSize = 16
		tc.want = want

		return
	}

	tests := []testCase{
		newTestCase(
			"challenge_8_true",
			"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf"+
				"9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a"+
				"08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4f"+
				"d5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
			true,
		),
		newTestCase(
			"challenge_8_false",
			"b563aac8275730bd4cf89ab32bb4b152be8fae16afab58ab3ea0e825c8ce28ddbe26c8cafef763f1"+
				"d9c3f30d60335cd0b765b98a11d5cfbe7a2d75e8f8a5e851ee6a17de174d8bea5c1e089beffc9970"+
				"9d6dcc03e578220eccdfa99d3fa0a3d2f6736de041cd783ad7f866df5dcd2a752cfbfc380cf84da5"+
				"c5dd3fc486cf1adc14d29d9e91737514e8c67d5c5aece4a19216e2b069f53b8ab4acaef17f815004",
			false,
		),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AesEcbDetect(tt.args.inBytes, tt.args.blockSize); got != tt.want {
				t.Errorf("AesEcbDetect() = %v, want %v", got, tt.want)
			}
		})
	}
}
