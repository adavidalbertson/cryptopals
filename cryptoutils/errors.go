package cryptoutils

// Removing all panics from cryptoUtils.
// Currently there are no call stacks deep enought to necessitate panics.
// This will be deleted once all calls to it are removed.
func check(e error) {
	if e != nil {
		panic(e)
	}
}
