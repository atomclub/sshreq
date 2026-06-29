package crypto

import (
	"crypto/rand"
	"log/slog"

	. "github.com/atomclub/sshreq/base64bytes"
	"golang.org/x/crypto/curve25519"
)

func NewKeypair() Keypair {
	priv := make([]byte, curve25519.ScalarSize)
	rand.Read(priv)

	keypair := Keypair{priv}

	slog.Debug("generating keypair", "private", Bytes(priv).String(), "public", Bytes(keypair.PublicKey()).String())

	return keypair
}

func NewKeypairWithKey(privateKey []byte) Keypair {
	if len(privateKey) != curve25519.ScalarSize {
		panic("invalic private key!")
	}

	keypair := Keypair{privateKey}

	slog.Debug("generating keypair", "private", Bytes(privateKey).String(), "public", Bytes(keypair.PublicKey()).String())

	return keypair
}

type Keypair struct {
	privateKey []byte
}

func (k *Keypair) PublicKey() []byte {
	pub, err := curve25519.X25519(k.privateKey, curve25519.Basepoint)
	if err != nil {
		panic(err.Error())
	}

	return pub
}

func (k *Keypair) PrivateKey() []byte {
	return k.privateKey
}
