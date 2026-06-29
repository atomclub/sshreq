package main

// `sshgen` is an internal tool to verify a CSR and sign a certificate.

// Usage:
// 	sshgen -f [private_key] -i [interval]

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/atomclub/sshreq"
	. "github.com/atomclub/sshreq/base64bytes"
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
	viper.SetConfigName("configca")
	viper.SetConfigType("yaml")

	userConfigDir, err := os.UserConfigDir()
	fatalIf("parse user config", err)

	configPath := filepath.Join(userConfigDir, "sshreq")

	if _, err := os.ReadDir(configPath); os.IsNotExist(err) {
		err = os.Mkdir(configPath, 0o755)
		fatalIf("get config dir", err)
	}

	viper.AddConfigPath(configPath)
	viper.AddConfigPath(".")

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
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// it's not simply NotFound
			fatalIf("reading config", err)
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

	if err := viper.WriteConfigAs("configca.yaml"); err != nil {
		panic(err)
	}

	signer := sshreq.GetSigner(sshCaKeyPath)

	csr := requestPaste()

	err = csr.VerifySignature()
	fatalIf("verifying signature", err)

	slog.Debug("verifing with", "X25519PrivateKey", Bytes(X25519CAPrivateKey).String())
	err = csr.VerifyToken(X25519CAPrivateKey)
	fatalIf("verifying token", err)

	fmt.Println("verified!")
	SSHUserKey, err := ssh.ParsePublicKey(csr.PublicKey)
	fatalIf("parsing public key", err)

	cert := &ssh.Certificate{
		Key:      SSHUserKey,
		CertType: ssh.UserCert,

		ValidPrincipals: []string{"atom", "picasol"},

		// TODO: parse valid period in csr
		ValidAfter:  uint64(time.Now().UTC().Unix()),
		ValidBefore: uint64(time.Now().UTC().Add(30 * 24 * time.Hour).Unix()),

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
