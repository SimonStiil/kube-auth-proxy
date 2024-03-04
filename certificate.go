package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

// Good documentation:
//https://gist.github.com/samuel/8b500ddd3f6118d052b5e6bc16bc4c09
//https://gist.github.com/gambol99/d55afd69217b8e2dd727be99f0a20e7d

func CreateEllipticKey() (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	return out.String(), nil
}

func CreateEllipticCSR() (string, error) {
	x509.
}