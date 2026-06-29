package main

// `sshreq` is an internal tool used to generate a CSR.

// Usage:
// 	sshreq -f [private_key] -i [interval]

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/atomclub/sshreq"
	. "github.com/atomclub/sshreq/base64bytes"

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
	fatalIf("get config dir", err)

	configDir := filepath.Join(userConfigDir, "sshreq")
	if _, err := os.ReadDir(configDir); os.IsNotExist(err) {
		err = os.Mkdir(configDir, 0o755)
		fatalIf("creating config dir", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")
	viper.SetConfigFile(configPath)

	flagSet := flag.CommandLine
	verbose := flagSet.BoolP("verbose", "v", false, "show debug message")
	help := flagSet.BoolP("help", "h", false, "show help message")
	privateKeyPath := flagSet.StringP("private-key", "f", "", "ssh private key")
	interval := flagSet.StringP("interval", "i", "+1m", "certificate interval")

	refreshTokenFlag := &flag.Flag{
		Name:      "token",
		Shorthand: "t",
		Usage:     "github login refreshToken",
		Value:     sshreq.NewStringValue("", new(string)),
		DefValue:  "",
	}
	flagSet.AddFlag(refreshTokenFlag)
	_ = viper.BindPFlag("token", refreshTokenFlag)

	caKeyBase64 := &flag.Flag{
		Name:      "ca-key",
		Shorthand: "c",
		Usage:     "ca x25519 key",
		Value:     sshreq.NewStringValue("", new(string)),
		DefValue:  "",
	}
	flagSet.AddFlag(caKeyBase64)
	_ = viper.BindPFlag("ca-key", caKeyBase64)

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

	if *privateKeyPath == "" || *help || viper.GetString("ca-key") == "" {
		fmt.Println("Usage: `sshreq -f [private_key] -i [interval] -c [ca key base64]`")
		flagSet.PrintDefaults()
		os.Exit(0)
	}

	var token string
	token = viper.GetString("token")
	if token == "" {
		token, err = sshreq.RequestLogin()
		fatalIf("require login to get token", err)
	}

	viper.Set("token", token)
	fatalIf("write config", viper.WriteConfig())

	X25519CaKey := NewBytes(viper.GetString("ca-key"))

	csr := sshreq.NewCsr(*privateKeyPath, interval, viper.GetString("token"), X25519CaKey)
	csrString, err := json.Marshal(csr)
	fatalIf("marshaling json output", err)

	fmt.Println(string(csrString))
}
