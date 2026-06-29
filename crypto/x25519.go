package crypto

import (
	"crypto/sha256"
	"io"
	"log/slog"

	. "github.com/atomclub/sshreq/base64bytes"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func Encrypt(RecipientPublicKey []byte, SenderKeyPair Keypair, payload []byte) (cipher []byte, err error) {
	sharedKey, err := curve25519.X25519(SenderKeyPair.PrivateKey(), RecipientPublicKey)
	slog.Debug("computed sharedKey", "key", Bytes(sharedKey).String())
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 0, len(SenderKeyPair.PublicKey())+len(RecipientPublicKey))
	salt = append(salt, SenderKeyPair.PublicKey()...)
	salt = append(salt, RecipientPublicKey...)
	slog.Debug("get salt", "salt", Bytes(salt).String())

	// derive a key for symmetric encryption
	h := hkdf.New(sha256.New, sharedKey, salt, []byte("X25519"))
	encryptKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, encryptKey)

	cipher, err = aeadEncrypt(encryptKey, payload)
	return
}

func EphemeralEncrypt(RecipientPublicKey, payload []byte) (SenderPublicKey, cipher []byte, err error) {
	k := NewKeypair()
	cipher, err = Encrypt(RecipientPublicKey, k, payload)
	return k.PublicKey(), cipher, err
}

func Decrypt(CaKeypair Keypair, X25519UserKey, cipher []byte) (payload []byte, err error) {
	sharedKey, err := curve25519.X25519(CaKeypair.PrivateKey(), X25519UserKey)
	slog.Debug("computed sharedKey", "key", Bytes(sharedKey).String())
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 0, len(CaKeypair.PublicKey())+len(X25519UserKey))
	// revert the order
	salt = append(salt, X25519UserKey...)
	salt = append(salt, CaKeypair.PublicKey()...)
	slog.Debug("get salt", "salt", Bytes(salt).String())

	h := hkdf.New(sha256.New, sharedKey, salt, []byte("X25519"))
	encryptKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, encryptKey)

	payload, err = aeadDecrypt(encryptKey, cipher)
	return
}
