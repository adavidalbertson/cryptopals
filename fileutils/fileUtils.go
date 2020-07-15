package fileutils

import (
	"bufio"
	"os"
	"path/filepath"
)

// Identity converts a string directly to a byte slice with no decoding.
// Used as a stand-in decode arg for fileutil functions
func Identity(input string) ([]byte, error) {
	return []byte(input), nil
}

// BytesFromFile reads bytes from a text file using the given decode function, and returns the contents of
// the entire file as a single byte slice
func BytesFromFile(fname string, decode func(line string) (bytes []byte, err error)) (bytes []byte, err error) {
	byteSlices, err := ByteSlicesFromFile(fname, decode)

	for _, lineBytes := range byteSlices {
		bytes = append(bytes, lineBytes...)
	}

	return
}

// ByteSlicesFromFile reads bytes from a text file using the given decode function, and returns a byte slice
// for each line read
func ByteSlicesFromFile(fname string, decode func(line string) ([]byte, error)) (byteSlices [][]byte, err error) {
	absPath, err := filepath.Abs(fname)
	if err != nil {
		return
	}

	file, err := os.Open(absPath)
	defer file.Close()
	if err != nil {
		return
	}

	read := bufio.NewScanner(file)

	for read.Scan() {
		lineBytes, err := decode(read.Text())
		if err != nil {
			return byteSlices, err
		}

		byteSlices = append(byteSlices, lineBytes)
	}

	return
}
