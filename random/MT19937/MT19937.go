package MT19937

import (
	"encoding/binary"
	"fmt"
	"github.com/adavidalbertson/cryptopals/random"
	"github.com/adavidalbertson/cryptopals/xor"
	"math/rand"
	"time"
)

const n, m, r = 624, 397, 31
const a = 0x9908B0DF
const u, d = 11, 0xFFFFFFFF
const s, b = 7, 0x9D2C5680
const t, c = 15, 0xEFC60000
const l = 18
const f = 1812433253
const lowerMask = 0x7FFFFFFF
const upperMask = 0x80000000

// Twister stores the internal state of the Mersenne Twister PRNG.
// Cryptopals Set 3, Challenge 21
// https://cryptopals.com/sets/3/challenges/21
type Twister struct {
	index int
	seed  uint32
	mt    [n]uint32
}

// CtrCipher is a stream cipher which uses a Mersenne Twister PRNG as the pad.
// Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
type CtrCipher struct {
	encrypter, decrypter Twister
	key                  uint16
}

type CtrOracle struct {
	key    uint16
	cipher CtrCipher
}

//Init initializes a new Mersenne Twister PRNG with the given seed.
// Cryptopals Set 3, Challenge 21
// https://cryptopals.com/sets/3/challenges/21
func Init(seed uint32) Twister {
	var mt [n]uint32
	index := n

	mt[0] = seed
	for i := 1; i < n; i++ {
		mt[i] = (uint32(f)*(mt[i-1]^(mt[i-1]>>30)) + uint32(i))
	}

	return Twister{index, seed, mt}
}

// twist scrambles the internal structure of the Mersenne Twister PRNG so it can keep producting pseudorandom numbers.
// Cryptopals Set 3, Challenge 21
// https://cryptopals.com/sets/3/challenges/21
func (twister *Twister) twist() {
	for i := 0; i < n; i++ {
		x := (twister.mt[i] & upperMask) + (twister.mt[(i+1)%n] & lowerMask)
		xA := x >> 1

		if x%2 != 0 {
			xA ^= a
		}

		twister.mt[i] = twister.mt[(i+m)%n] ^ xA
	}

	twister.index = 0
}

// Extract produces the next pseudorandom output.
// It also performs twist when the internal state needs updating.
// Cryptopals Set 3, Challenge 21
// https://cryptopals.com/sets/3/challenges/21
func (twister *Twister) Extract() uint32 {
	i := twister.index
	if twister.index >= n {
		twister.twist()
		i = twister.index
	}

	twister.index = i + 1

	y := temper(twister.mt[i])

	return y
}

// temper applies tempering bit shifts and masks.
// Cryptopals Set 3, Challenge 21
// https://cryptopals.com/sets/3/challenges/21
func temper(y uint32) uint32 {
	y ^= (y >> u)
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= (y >> l)

	return y
}

// SetMT sets the internal state of a Mersenne Twister PRNG to the one given.
// Cryptopals Set 3, Challenge 23
// https://cryptopals.com/sets/3/challenges/23
func (twister *Twister) SetMT(mt [n]uint32) {
	twister.mt = mt
}

// SetIndex sets the internal index of a Mersenne Twister PRNG to the one given.
// Cryptopals Set 3, Challenge 23
// https://cryptopals.com/sets/3/challenges/23
func (twister *Twister) SetIndex(i int) {
	twister.index = i
}

// TimeSeed sleeps for a random interval, seeds a Mersenne Twister PRNG with
// the current time, extracts a pseudorandom number, then sleeps for another
// random interval before returning.
// Cryptopals Set 3, Challenge 22
// https://cryptopals.com/sets/3/challenges/22
func TimeSeed(minWait, maxWait int) uint32 {
	maxWait -= minWait
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	before := time.Duration(minWait+r.Intn(maxWait)) * time.Second
	after := time.Duration(minWait+r.Intn(maxWait)) * time.Second

	time.Sleep(before)

	seed := uint32(time.Now().Unix())
	fmt.Println("Intitializing twister with timed seed:", seed)
	twister := Init(seed)
	out := twister.Extract()

	time.Sleep(after)

	return out
}

// NewCtrCipher creates a new MT19937 CTR cipher with a given seed (key).
// Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
func NewCtrCipher(key uint16) CtrCipher {
	encrypter := Init(uint32(key))
	decrypter := Init(uint32(key))

	return CtrCipher{encrypter, decrypter, key}
}

// encryptStream XORs the text with the output of the Mersenne Twister.
// Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
func (twister *Twister) encryptStream(plaintext []byte) []byte {
	blockSize := 4
	var keyStream []byte
	ciphertext := make([]byte, len(plaintext))

	for i := 0; i <= len(plaintext); i += blockSize {
		k := make([]byte, 4)
		binary.LittleEndian.PutUint32(k, twister.Extract())
		keyStream = append(keyStream, k...)
	}

	keyStream = keyStream[:len(plaintext)]
	ciphertext, _ = xor.Xor(plaintext, keyStream)

	return ciphertext
}

// Encrypt the plaintext using the MT19937 CTR cipher.
// Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
func (cipher *CtrCipher) Encrypt(ciphertext []byte) []byte {
	return cipher.encrypter.encryptStream(ciphertext)
}

// Decrypt the ciphertext using the MT19937 CTR cipher.
// Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
func (cipher *CtrCipher) Decrypt(ciphertext []byte) []byte {
	return cipher.decrypter.encryptStream(ciphertext)
}

// NewCtrOracle inits a new MT19937 CTR encryption oracle.
// Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
func NewCtrOracle() CtrOracle {
	key := binary.LittleEndian.Uint16(random.Bytes(2))
	cipher := NewCtrCipher(key)

	return CtrOracle{key, cipher}
}

// Encrypt appends a random prefix to a plaintext and encrypts it with the
// MT19937 CTR cipher.
// Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
func (oracle *CtrOracle) Encrypt(plaintext []byte) []byte {
	return oracle.cipher.Encrypt(random.Prefix(plaintext))
}

func PasswordResetToken() uint32 {
	return TimeSeed(2, 10)

}
