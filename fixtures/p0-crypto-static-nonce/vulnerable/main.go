package main

import (
	"crypto/aes"
	"crypto/cipher"
)

func seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Vulnerable: static zero nonce reused across messages
	nonce := make([]byte, 12)
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}
