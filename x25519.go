package sshreq

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log/slog"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	// use fixed nonce here since we generate a new key every time.

	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func Encrypt(theirKey, payload []byte) (ourKey, cipherText []byte, err error) {
	ephemeralKey := make([]byte, curve25519.ScalarSize)
	rand.Read(ephemeralKey)
	ourKey, err = curve25519.X25519(ephemeralKey, curve25519.Basepoint)
	slog.Debug("get ephemeralKey", "private", Bytes(ephemeralKey).String(), "public", Bytes(ourKey).String())
	if err != nil {
		return nil, nil, err
	}

	sharedKey, err := curve25519.X25519(ephemeralKey, theirKey)
	slog.Debug("computed sharedKey", "key", Bytes(sharedKey).String())
	if err != nil {
		return nil, nil, err
	}

	salt := make([]byte, 0, len(ourKey)+len(theirKey))
	salt = append(salt, ourKey...)
	salt = append(salt, theirKey...)
	slog.Debug("get salt", "salt", Bytes(salt).String())

	h := hkdf.New(sha256.New, sharedKey, salt, []byte("X25519"))
	encryptKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, encryptKey)

	cipherText, err = aeadEncrypt(encryptKey, payload)
	return
}

func aeadDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)

	return aead.Open(nil, nonce, ciphertext, nil)
}

func Decrypt(ourKey, theirKey, cipher []byte) (payload []byte, err error) {
	sharedKey, err := curve25519.X25519(ourKey, theirKey)
	slog.Debug("computed sharedKey", "key", Bytes(sharedKey).String())
	if err != nil {
		return nil, err
	}

	pub, err := curve25519.X25519(ourKey, curve25519.Basepoint)
	slog.Debug("computed pub", "key", Bytes(pub).String())
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 0, len(ourKey)+len(theirKey))
	// revert the order
	salt = append(salt, theirKey...)
	salt = append(salt, pub...)
	slog.Debug("get salt", "salt", Bytes(salt).String())

	h := hkdf.New(sha256.New, sharedKey, salt, []byte("X25519"))
	encryptKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, encryptKey)

	payload, err = aeadDecrypt(encryptKey, cipher)
	return
}
