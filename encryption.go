package main

import (
	"crypto/aes"
)

// Good documentation:
// https://dev.to/breda/secret-key-encryption-with-go-using-aes-316d

var (
	// We're using a 32 byte long secret key
	secretKey string = "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"
)

func encrypt(plaintext string) string {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	// Make a buffer the same length as plaintext
	ciphertext := make([]byte, len(plaintext))
	aes.Encrypt(ciphertext, []byte(plaintext))

	return string(ciphertext)
}
