package main

/// `sshreq` is an internal tool used to generate a CSR.

/// Usage:
/// 	sshreq -f [private_key] -p [public_key] -i [interval]

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/bgentry/speakeasy"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

// Csr represents the certificate signing request.
type Csr struct {
	// SSH public key
	PublicKey string `json:"publicKey"`

	// Certificate valid interval, default "+1d"
	Interval string `json:"interval"`

	// Signature is the csr signed by privateKey, when signing the signature field is omitted.
	Signature string `json:"signature,omitempty"`
}

func ExitOnError(err error) {
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func main() {
	flags := flag.CommandLine
	verbose := flags.BoolP("verbose", "v", false, "show debug message")
	help := flags.BoolP("help", "h", false, "show help message")
	privateKeyPath := flags.StringP("private-key", "f", "", "ssh private key")
	interval := flags.StringP("interval", "i", "+1w", "certificate interval")

	flags.SortFlags = false
	err := flags.Parse(os.Args)
	ExitOnError(err)

	slog.SetLogLoggerLevel(slog.LevelInfo)
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if *privateKeyPath == "" || *help {
		fmt.Println("Usage: sshreq -f [private_key] -p [public_key] -i [interval]")
		flags.PrintDefaults()
		os.Exit(0)
	}

	privateKeyBytes, err := os.ReadFile(*privateKeyPath)
	slog.Debug("reading private key: ", "path", *privateKeyPath)
	ExitOnError(err)

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		switch err.(type) {
		case *ssh.PassphraseMissingError:

			slog.Debug("private key is encrypted, asking passphrase")

			passphrase, err := speakeasy.Ask("enter passphrase: ")
			ExitOnError(err)

			slog.Debug("parsing private key with passphrase: ", "path", *privateKeyPath)
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase))
			ExitOnError(err)
		default:
			ExitOnError(err)
		}
	}
	if signer == nil {
		panic("signer is nil!")
	}
	slog.Debug("initialized signer")

	csr := Csr{
		PublicKey: string(bytes.TrimRight(ssh.MarshalAuthorizedKey(signer.PublicKey()), "\n")),
		Interval:  *interval,
	}

	payload, err := json.Marshal(csr)
	ExitOnError(err)
	slog.Debug("generated payload", "payload", string(payload))

	signature, err := signer.Sign(rand.Reader, payload)
	ExitOnError(err)

	sig := base64.StdEncoding.EncodeToString(signature.Blob)
	slog.Debug("generated signature", "signature", sig)
	csr.Signature = sig

	rawCsr, err := json.Marshal(csr)
	ExitOnError(err)
	fmt.Printf("%s", string(rawCsr))
}
