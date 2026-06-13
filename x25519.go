package main

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func Encrypt(theirKey, payload []byte) (ourKey, cipherText []byte, err error) {
	ephemeralKey := make([]byte, curve25519.ScalarSize)
	rand.Read(ephemeralKey)
	ourKey, err = curve25519.X25519(ephemeralKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	sharedKey, err := curve25519.X25519(ephemeralKey, theirKey)
	if err != nil {
		return nil, nil, err
	}

	salt := make([]byte, 0, len(ourKey)+len(theirKey))
	salt = append(salt, ourKey...)
	salt = append(salt, theirKey...)

	h := hkdf.New(sha256.New, sharedKey, salt, []byte("X25519"))
	encryptKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, encryptKey)

	cipherText, err = aeadEncrypt(encryptKey, payload)
	return
}

func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(nonce)

	return aead.Seal(nil, nonce, plaintext, nil), nil
}
