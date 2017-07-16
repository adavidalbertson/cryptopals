package attacks

import (
	"bytes"
    "encoding/binary"
	"github.com/adavidalbertson/cryptopals/random/MT19937"
	"runtime"
	"sync"
)

// just repeat these here for now.
const n, m, r = 624, 397, 31
const a = 0x9908B0DF
const u, d = 11, 0xFFFFFFFF
const s, b = 7, 0x9D2C5680
const t, c = 15, 0xEFC60000
const l = 18
const f = 1812433253

// CloneMT19937 creates a new MT19937 PRNG with the same internal state
// (and thus the same output) as the provided one.
// for Cryptopals Set 3, Challenge 23
// https://cryptopals.com/sets/3/challenges/23
func CloneMT19937(twister *MT19937.Twister) MT19937.Twister {
	var mt [n]uint32
	for i := range mt {
		mt[i] = Untemper(twister.Extract())
	}

	clone := MT19937.Init(uint32(0x1))
	clone.SetMT(mt)
	clone.SetIndex(n)

	return clone
}

// Untemper reverses the tempering transformation of an MT19937 pseudorandom
// output to determine the entry in mt that produced it.
// for Cryptopals Set 3, Challenge 23
// https://cryptopals.com/sets/3/challenges/23
func Untemper(y uint32) uint32 {
	y = undoRight(y, l)
	y = undoLeft(y, c, t)
	y = undoLeft(y, b, s)
	y = undoRight(y, u)

	return y
}

// undoRight reverses the right shift transformation in MT19937.
// for Cryptopals Set 3, Challenge 23
// https://cryptopals.com/sets/3/challenges/23
func undoRight(y uint32, d int) uint32 {
	for i := 0; i < 32-d; i++ {
		y ^= ((0x1 << uint(31-i)) & y) >> uint(d)
	}

	return y
}

// undoLeft reverses the left shift transformation in MT19937.
// for Cryptopals Set 3, Challenge 23
// https://cryptopals.com/sets/3/challenges/23
func undoLeft(y, x uint32, d int) uint32 {
	z := uint32(0x0)
	for i := 0; i < 32; i++ {
		b := ((0x1 << uint(i)) & y) ^ (((0x1 << uint(i)) & (z << uint(d))) & ((0x1 << uint(i)) & x))
		z ^= b
	}

	return z
}

// BreakMT19937CtrOracle recovers the cipher's key using a known plaintext attack.
// for Cryptopals Set 3, Challenge 24
// https://cryptopals.com/sets/3/challenges/24
func BreakMT19937CtrOracle(oracle MT19937.CtrOracle) uint16 {
	w := make([]byte, 4)
    binary.LittleEndian.PutUint32(w, 0xAAAAAAAA)
	plaintext := bytes.Repeat(w, 4)

	ciphertext := oracle.Encrypt(plaintext)

	cores := runtime.NumCPU()
    keyChan := make(chan uint32, 1<<16)
	defer close(keyChan)
    cancelChan := make(chan int, cores)
	defer close(cancelChan)

    for i := 0; i < 1<<16; i++ {
        keyChan <- uint32(i)
    }

    successChans := make([]<-chan uint32, cores)
    for i := 0; i < cores; i++ {
        successChans[i] = tryKeys(keyChan, cancelChan, plaintext, ciphertext)
    }

    key := <-merge(successChans, cancelChan)

    for i := 0; i < cores; i++ {
        cancelChan <- 0
    }

	return uint16(key)
}

// RecoverTimedSeed recovers the time used as a seed for a Mersenne Twister PRNG
// for Cryptopals Set 3, Challenge 22
// https://cryptopals.com/sets/3/challenges/22
func RecoverTimedSeed(before, after int64, token uint32) uint32 {
	cores := runtime.NumCPU()
    seedChan := make(chan uint32, after - before + 1)
	defer close(seedChan)
    cancelChan := make(chan int, cores)
	defer close(cancelChan)

	for i := before; i <= after; i++ {
        seedChan <- uint32(i)
    }

    successChans := make([]<-chan uint32, cores)
    for i := 0; i < cores; i++ {
        successChans[i] = trySeeds(seedChan, cancelChan, token)
    }

    seed := <-merge(successChans, cancelChan)

    for i := 0; i < cores; i++ {
        cancelChan <- 0
    }

	return seed
}

func tryKeys(in <-chan uint32, cancel <-chan int, plaintext, ciphertext []byte) <-chan uint32 {
    out := make(chan uint32)
    go func() {
        for key := range in {
			// Stop trying if we already found it.
			select {
			case <-cancel:
				return
			default:
			}
            cipher := MT19937.NewCtrCipher(uint16(key))
            decrypted := cipher.Decrypt(ciphertext)
            if bytes.HasSuffix(decrypted, plaintext) {
				// Ensure that we don't send on a closed channel.
                select {
                case out <- key:
                    return
                case <-cancel:
                    return
                }
            }
        }
        close(out)
    }()
    return out
}

func trySeeds(in <-chan uint32, cancel <-chan int, token uint32) <-chan uint32 {
    out := make(chan uint32)
    go func() {
        for seed := range in {
			// Stop trying if we already found it.
			select {
			case <-cancel:
				return
			default:
			}
            twister := MT19937.Init(seed)
            if twister.Extract() == token {
				// Ensure that we don't send on a closed channel.
                select {
                case out <- seed:
                    return
                case <-cancel:
                    return
                }
            }
        }
        close(out)
    }()
    return out
}

func merge(cs []<-chan uint32, cancel <-chan int) <-chan uint32 {
    var wg sync.WaitGroup
    out := make(chan uint32, 1)

    output := func(c <-chan uint32) {
		// Stop trying if we already found it.
		select {
		case <-cancel:
			return
		default:
		}
        defer wg.Done()
        for key := range c {
			// Ensure that we don't send on a closed channel.
            select {
            case out <- key:
                return
            case <-cancel:
                return
            }
        }
    }

    wg.Add(len(cs))
    for _, c := range cs {
        go output(c)
    }

    go func() {
        wg.Wait()
        close(out)
    }()

    return out
}
