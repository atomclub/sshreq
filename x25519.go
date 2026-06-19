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

func Encrypt(X25519CaKey, payload []byte) (X25519UserKey, cipherText []byte, err error) {
	X25519UserPrivateKey := make([]byte, curve25519.ScalarSize)
	rand.Read(X25519UserPrivateKey)
	X25519UserKey, err = curve25519.X25519(X25519UserPrivateKey, curve25519.Basepoint)
	slog.Debug("get ephemeralKey", "private", Bytes(X25519UserPrivateKey).String(), "public", Bytes(X25519UserKey).String())
	if err != nil {
		return nil, nil, err
	}

	sharedKey, err := curve25519.X25519(X25519UserPrivateKey, X25519CaKey)
	slog.Debug("computed sharedKey", "key", Bytes(sharedKey).String())
	if err != nil {
		return nil, nil, err
	}

	salt := make([]byte, 0, len(X25519UserKey)+len(X25519CaKey))
	salt = append(salt, X25519UserKey...)
	salt = append(salt, X25519CaKey...)
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

func Decrypt(X25519CaPrivateKey, X25519UserKey, cipher []byte) (payload []byte, err error) {
	sharedKey, err := curve25519.X25519(X25519CaPrivateKey, X25519UserKey)
	slog.Debug("computed sharedKey", "key", Bytes(sharedKey).String())
	if err != nil {
		return nil, err
	}

	X25519CaKey, err := curve25519.X25519(X25519CaPrivateKey, curve25519.Basepoint)
	slog.Debug("computed pub", "key", Bytes(X25519CaKey).String())
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 0, len(X25519CaPrivateKey)+len(X25519UserKey))
	// revert the order
	salt = append(salt, X25519UserKey...)
	salt = append(salt, X25519CaKey...)
	slog.Debug("get salt", "salt", Bytes(salt).String())

	h := hkdf.New(sha256.New, sharedKey, salt, []byte("X25519"))
	encryptKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, encryptKey)

	payload, err = aeadDecrypt(encryptKey, cipher)
	return
}
