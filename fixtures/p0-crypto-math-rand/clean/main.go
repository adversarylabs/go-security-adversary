package main

import (
	"crypto/rand"
	"encoding/hex"
)

func sessionToken() string {
	// Clean: crypto/rand for session tokens
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
