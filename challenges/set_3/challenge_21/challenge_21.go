package main

import (
    "fmt"
    "github.com/adavidalbertson/cryptopals/random/MT19937"
    // "strconv"
)

// expected output:
// 1791095845
// 4282876139
// 3093770124
// 4005303368
// 491263

func main() {
    twister := MT19937.Init(0x1)

    for i := 0; i < 5; i++ {
        out := twister.Extract()
        fmt.Println(out)
    }
}
