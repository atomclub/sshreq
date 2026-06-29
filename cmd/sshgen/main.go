package main

// `sshgen` is an internal tool to verify a CSR and sign a certificate.

// Usage:
// 	sshgen -f [private_key] -i [interval]

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atomclub/sshreq"

	. "github.com/atomclub/sshreq/base64bytes"
	"github.com/atomclub/sshreq/duration"
	"golang.org/x/crypto/ssh"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func fatalIf(msg string, err error) {
	if err != nil {
		log.Fatalf("%s failed: %s", msg, err.Error())
	}
}

func main() {
	userConfigDir, err := os.UserConfigDir()
	fatalIf("parse user config", err)

	configDir := filepath.Join(userConfigDir, "sshreq")
	if _, err := os.ReadDir(configDir); os.IsNotExist(err) {
		err = os.Mkdir(configDir, 0o755)
		fatalIf("get config dir", err)
	}

	configPath := filepath.Join(userConfigDir, "sshgen.yaml")
	viper.SetConfigFile(configPath)

	flagSet := flag.CommandLine
	verbose := flagSet.BoolP("verbose", "v", false, "show debug message")
	help := flagSet.BoolP("help", "h", false, "show help message")
	_ = flagSet.BoolP("confirm", "y", false, "silently confirm")

	SSHCAKey := &flag.Flag{
		Name:      "ssh-ca-key",
		Shorthand: "s",
		Usage:     "SSH CA private key",
		Value:     sshreq.NewStringValue("", new(string)),
		DefValue:  "",
	}
	flagSet.AddFlag(SSHCAKey)
	_ = viper.BindPFlag("ssh-ca-key", SSHCAKey)

	caKey := &flag.Flag{
		Name:      "ca-key",
		Shorthand: "k",
		Usage:     "X25519 ca private key",
		Value:     sshreq.NewStringValue("", new(string)),
		DefValue:  "",
	}
	flagSet.AddFlag(caKey)
	_ = viper.BindPFlag("ca-key", caKey)

	flagSet.SortFlags = false
	err = flagSet.Parse(os.Args)
	fatalIf("parsing flag", err)

	if err := viper.ReadInConfig(); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			fatalIf("reading viper config", err)
		} else {
			_, _ = os.Create(configPath)
			viper.ReadInConfig()
		}
	}

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	} else {
		slog.SetLogLoggerLevel(slog.LevelInfo)
	}

	sshCaKeyPath := viper.GetString("ssh-ca-key")

	if viper.GetString("ca-key") == "" || *help || sshCaKeyPath == "" {
		fmt.Println("Usage: `sshgen -k [ca-private-key] [-y] -s [ssh-ca-private-key-path]`")
		flagSet.PrintDefaults()
		os.Exit(0)
	}

	X25519CAPrivateKey, err := base64.StdEncoding.DecodeString(viper.GetString("ca-key"))
	slog.Debug("got X25519CAPrivateKey", "key", Bytes(X25519CAPrivateKey).String())
	fatalIf("ca-key (x25519) decode", err)

	fatalIf("write config", viper.WriteConfig())

	signer := sshreq.GetSigner(sshCaKeyPath)

	csr := requestPaste()

	// ensure the generator has the corresponding ssh private key
	err = csr.VerifySignature()
	fatalIf("verifying signature", err)

	slog.Debug("verifing with", "X25519PrivateKey", Bytes(X25519CAPrivateKey).String())
	err = csr.VerifyToken(X25519CAPrivateKey)
	fatalIf("verifying token", err)

	SSHUserKey, err := ssh.ParsePublicKey(csr.PublicKey)
	fatalIf("parsing public key", err)

	// parse duration like +1m2w12h
	d := strings.TrimPrefix(csr.Interval, "+")
	duration, err := duration.ParseDuration(d)
	fatalIf("parsing duration", err)
	validBefore := time.Now().Add(time.Duration(duration)).UTC()

	cert := &ssh.Certificate{
		Key:      SSHUserKey,
		CertType: ssh.UserCert,

		ValidPrincipals: []string{"atom", "picasol"},

		// TODO: parse valid period in csr
		ValidAfter:  uint64(time.Now().UTC().Unix()),
		ValidBefore: uint64(validBefore.Unix()),

		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	err = cert.SignCert(rand.Reader, signer)
	fatalIf("signing cert", err)

	fmt.Println(string(ssh.MarshalAuthorizedKey(cert)))
}

func requestPaste() *sshreq.Csr {
	csr := &sshreq.Csr{}
	var csrString []byte
	fmt.Print("Paste csr json here: ")
	_, err := fmt.Scan(&csrString)
	fatalIf("get input", err)

	err = json.Unmarshal(csrString, csr)
	fatalIf("parsing csr", err)

	return csr
}
