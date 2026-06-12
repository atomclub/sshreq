package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/bgentry/speakeasy"
	"golang.org/x/crypto/ssh"
)

type AuthProvider string

const (
	Github                  AuthProvider = "github"
	CaX25519PublicKeyBase64 string       = ""
)

// Csr represents the certificate signing request.
type Csr struct {
	// SSH public key
	PublicKey string `json:"publicKey"`

	// Certificate valid interval, default "+1d"
	Interval string `json:"interval"`

	// Third party auth provider, currently only "github" is allowed
	AuthProvider AuthProvider `json:"auth_provider"`

	// Oauth Token to get user email from AuthProvider
	Token string `json:"token"`

	// Signature is the csr signed by privateKey, when signing the signature field is omitted.
	Signature string `json:"signature,omitempty"`
}

func generateCsr(privateKeyPath *string, interval *string, token string) string {
	privateKeyBytes, err := os.ReadFile(*privateKeyPath)
	slog.Debug("reading private key: ", "path", *privateKeyPath)
	ExitIf(err)

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		switch err.(type) {
		case *ssh.PassphraseMissingError:
			slog.Debug("private key is encrypted, asking passphrase")

			passphrase, err := speakeasy.Ask("enter passphrase: ")
			ExitIf(err)

			slog.Debug("parsing private key with passphrase: ", "path", *privateKeyPath)
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase))
			ExitIf(err)

		default:
			ExitIf(err)
		}
	}
	if signer == nil {
		panic("signer is nil!")
	}
	slog.Debug("initialized signer")

	csr := Csr{
		PublicKey:    string(bytes.TrimRight(ssh.MarshalAuthorizedKey(signer.PublicKey()), "\n")),
		Interval:     *interval,
		AuthProvider: Github,
		Token:        token,
	}

	payload, err := json.Marshal(csr)
	ExitIf(err)
	slog.Debug("generated payload", "payload", string(payload))

	signature, err := signer.Sign(rand.Reader, payload)
	ExitIf(err)

	sig := base64.StdEncoding.EncodeToString(signature.Blob)
	slog.Debug("generated signature", "signature", sig)
	csr.Signature = sig

	rawCsr, err := json.Marshal(csr)
	ExitIf(err)
	return string(rawCsr)
}
