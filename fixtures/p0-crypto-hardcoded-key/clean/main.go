package main

import (
	"crypto/aes"
	"crypto/rand"
)

func cipherBlock(key []byte) (interface{}, error) {
	// Clean: key provided by caller (from KMS/env), not a literal
	if len(key) == 0 {
		key = make([]byte, 16)
		_, _ = rand.Read(key)
	}
	return aes.NewCipher(key)
}
