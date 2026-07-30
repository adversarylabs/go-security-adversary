package main

import (
	"math/rand"
	"encoding/hex"
)

func sessionToken() string {
	// Vulnerable: math/rand for a security token
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(b)
}
