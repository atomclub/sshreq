package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func main() {
	ephemeral := make([]byte, curve25519.ScalarSize)
	rand.Read(ephemeral)
	ourPublicKey, err := curve25519.X25519(ephemeral, curve25519.Basepoint)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("X25519 Public Key: ", base64.StdEncoding.EncodeToString(ourPublicKey))
	fmt.Println("Private Key: ", base64.StdEncoding.EncodeToString(ephemeral))
}
