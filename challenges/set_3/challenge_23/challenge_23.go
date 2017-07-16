package main

import (
    "fmt"
    "github.com/adavidalbertson/cryptopals/attacks"
    "github.com/adavidalbertson/cryptopals/random/MT19937"
)

func main() {
    original := MT19937.Init(0x2)
    clone := attacks.CloneMT19937(&original)

    for i := 0; i < 10; i++ {
        originalOutput := original.Extract()
        cloneOutput := clone.Extract()

        fmt.Println(originalOutput, cloneOutput)

        if (cloneOutput != originalOutput) {
            panic("Outputs don't match!")
        }
    }

    fmt.Println("Success!")
}
