package sshreq

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	. "github.com/atomclub/sshreq/base64bytes"
	"github.com/atomclub/sshreq/crypto"
	"github.com/bgentry/speakeasy"
	"github.com/carlmjohnson/requests"
	"golang.org/x/crypto/ssh"
)

type AuthProvider string

const (
	Github AuthProvider = "github"
)

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err.Error())
		os.Exit(1)
	}
}

// Csr represents the certificate signing request.
type Csr struct {
	// SSH public key
	PublicKey Bytes `json:"publicKey"`

	// Certificate valid interval, default "+1d"
	Interval string `json:"interval"`

	// Third party auth provider, currently only "github" is allowed
	AuthProvider AuthProvider `json:"auth_provider"`

	// Oauth EncryptedToken to get user email from AuthProvider
	EncryptedToken Bytes `json:"encrypted_token"`

	// ephemeralKey is an ephemeral curve25519 public key.
	EphemeralKey Bytes `json:"ephemeral_key"`

	// Signature is the csr signed by privateKey, when signing the signature field is omitted.
	Signature Bytes `json:"signature,omitempty"`
}

func (c *Csr) MarshalJSON() ([]byte, error) {
	return json.Marshal(*c)
}

func GetSigner(privateKeyPath string) ssh.Signer {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	slog.Debug("reading private key: ", "path", privateKeyPath)
	fatalIf(err)

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		switch err.(type) {
		case *ssh.PassphraseMissingError:
			slog.Debug("private key is encrypted, asking passphrase")

			passphrase, err := speakeasy.Ask("enter passphrase: ")
			fatalIf(err)

			slog.Debug("parsing private key with passphrase: ", "path", privateKeyPath)
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase))
			fatalIf(err)

		default:
			fatalIf(err)
		}
	}
	if signer == nil {
		panic("signer is nil!")
	}
	slog.Debug("initialized signer")
	return signer
}

func NewCsr(privateKeyPath string, interval *string, token string, X25519CaKey []byte) *Csr {
	signer := GetSigner(privateKeyPath)

	slog.Debug("encrypt to ", "ca", Bytes(X25519CaKey).String())
	SenderPublicKey, encryptedToken, err := crypto.EphemeralEncrypt(X25519CaKey, []byte(token))
	fatalIf(err)

	csr := &Csr{
		PublicKey:      signer.PublicKey().Marshal(),
		Interval:       *interval,
		AuthProvider:   Github,
		EphemeralKey:   SenderPublicKey,
		EncryptedToken: encryptedToken,
	}

	payload, err := json.Marshal(csr)
	fatalIf(err)
	slog.Debug("generated payload")

	signature, err := signer.Sign(rand.Reader, payload)
	fatalIf(err)

	slog.Debug("generated signature")
	csr.Signature = ssh.Marshal(signature)
	return csr
}

func (c *Csr) VerifySignature() (err error) {
	publicKey, err := ssh.ParsePublicKey(c.PublicKey)
	if err != nil {
		slog.Debug("parse public key failed", "publickey", c.PublicKey)
		return
	}

	newCsr := &Csr{
		PublicKey:      c.PublicKey,
		Interval:       c.Interval,
		AuthProvider:   c.AuthProvider,
		EncryptedToken: c.EncryptedToken,
		EphemeralKey:   c.EphemeralKey,
	}

	csrWithoutSignature, err := json.Marshal(newCsr)
	slog.Debug("created json without signature field", "payload", string(csrWithoutSignature))
	if err != nil {
		return
	}

	sig := &ssh.Signature{}
	err = ssh.Unmarshal(c.Signature, sig)
	if err != nil {
		slog.Debug("ssh unmarshal failed")
		return
	}
	err = publicKey.Verify(csrWithoutSignature, sig)
	return
}

func (c *Csr) decryptToken(X25519CaPrivateKey []byte) (token string, err error) {
	tokenBytes, err := crypto.Decrypt(
		crypto.NewKeypairWithKey(X25519CaPrivateKey),
		c.EphemeralKey,
		c.EncryptedToken,
	)

	token = string(tokenBytes)
	return
}

type GithubResp struct {
	TwoFactorAuthentication bool   `json:"two_factor_authentication"` // present in resp when the token belongs to the user.
	Name                    string `json:"name"`
	URL                     string `json:"html_url"`
}

func (c *Csr) VerifyToken(X25519CaPrivateKey []byte) (err error) {
	token, err := c.decryptToken(X25519CaPrivateKey)
	if err != nil {
		return
	}

	if c.AuthProvider != Github {
		return errors.New("unsupported provider: " + string(c.AuthProvider))
	}
	resp := GithubResp{}
	err = requests.URL("https://api.github.com").
		Path("/user").
		Header("Accept", "application/vnd.github+json").
		Header("X-GitHub-Api-Version", "2026-03-10").
		Header("Authorization", "Bearer "+token).
		ToJSON(&resp).
		Fetch(context.Background())
	if err != nil {
		return err
	}

	fmt.Printf("user home page: %s\nuser name: %s\n confirm? [Y/n]", resp.URL, resp.Name)
	var input string
	_, _ = fmt.Scanf("%s\n", &input)

	if input == "Y" || input == "y" || input == "" {
		return
	} else {
		return errors.New("verification failed")
	}
}
