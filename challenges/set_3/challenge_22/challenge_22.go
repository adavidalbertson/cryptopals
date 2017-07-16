package main

import (
    "fmt"
    "github.com/adavidalbertson/cryptopals/random/MT19937"
    "time"
)

func main() {
    before := time.Now().Unix()
    timedRand := MT19937.TimeSeed(40, 1000)
    after := time.Now().Unix()
    fmt.Printf("Random uint32 from time: %d\n", timedRand)

    seed := uint32(0)

    for i := before; i <= after; i++ {
        mt := MT19937.Init(uint32(i))
        if (mt.Extract() == timedRand) {
            seed = uint32(i)
            break
        }
    }

    if (seed > 0) {
        fmt.Printf("Success! Matched seed: %d\n", seed)
    } else {
        fmt.Println("Fail")
    }
}
