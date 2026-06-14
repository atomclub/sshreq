package main

// `sshreq` is an internal tool used to generate a CSR.

// Usage:
// 	sshreq -f [private_key] -i [interval]

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/atomclub/sshreq"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("configca")
	viper.SetConfigType("yaml")

	userConfigDir, err := os.UserConfigDir()
	sshreq.ExitIf(err)
	configPath := filepath.Join(userConfigDir, "sshreq")

	if _, err := os.ReadDir(configPath); os.IsNotExist(err) {
		err = os.Mkdir(configPath, 0755)
		sshreq.ExitIf(err)
	}

	viper.AddConfigPath(configPath)
	viper.AddConfigPath(".")

	flagSet := flag.CommandLine
	verbose := flagSet.BoolP("verbose", "v", false, "show debug message")
	help := flagSet.BoolP("help", "h", false, "show help message")
	_ = flagSet.BoolP("confirm", "y", false, "silently confirm")

	caKey := &flag.Flag{
		Name:      "ca-key",
		Shorthand: "k",
		Usage:     "ssh ca private key",
		Value:     sshreq.NewStringValue("", new(string)),
		DefValue:  "",
	}
	flagSet.AddFlag(caKey)
	_ = viper.BindPFlag("ca-key", caKey)

	flagSet.SortFlags = false
	err = flagSet.Parse(os.Args)
	sshreq.ExitIf(err)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// it's not simply NotFound
			sshreq.ExitIf(err)
		}
	}

	slog.SetLogLoggerLevel(slog.LevelInfo)
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if caKey.Value.String() == "" || *help {
		fmt.Println("Usage: `sshgen -k [ca_private_key] [-y]`")
		flagSet.PrintDefaults()
		os.Exit(0)
	}

	ourKey, err := base64.StdEncoding.DecodeString(viper.GetString("ca-key"))
	slog.Debug("got ourKey", "key", sshreq.Bytes(ourKey).String())
	if err != nil {
		log.Fatal("ca-key decode failed: ", err.Error())
	}

	if err := viper.WriteConfigAs("configca.yaml"); err != nil {
		panic(err)
	}

	csr := &sshreq.Csr{}
	var csrString []byte
	fmt.Scan(&csrString)
	err = json.Unmarshal(csrString, csr)
	sshreq.ExitIf(err)

	err = csr.VerifySignature()
	if err != nil {
		log.Fatalf("verify signature failed: %s", err.Error())
		return
	}

	err = csr.VerifyToken(ourKey)
	slog.Debug("verifing with", "privkey", sshreq.Bytes(ourKey).String())
	if err != nil {
		log.Fatalf("verify token failed: %s", err.Error())
		return
	}

	fmt.Println("verified!")
}
