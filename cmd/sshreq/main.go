package main

// `sshreq` is an internal tool used to generate a CSR.

// Usage:
// 	sshreq -f [private_key] -i [interval]

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/atomclub/sshreq"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
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
	privateKeyPath := flagSet.StringP("private-key", "f", "", "ssh private key")
	interval := flagSet.StringP("interval", "i", "+1w", "certificate interval")

	refreshTokenFlag := &flag.Flag{
		Name:      "token",
		Shorthand: "t",
		Usage:     "github login refreshToken",
		Value:     sshreq.NewStringValue("", new(string)),
		DefValue:  "",
	}
	flagSet.AddFlag(refreshTokenFlag)
	_ = viper.BindPFlag("token", refreshTokenFlag)

	flagSet.SortFlags = false
	err = flagSet.Parse(os.Args)
	sshreq.ExitIf(err)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			sshreq.ExitIf(err)
		}
	}

	slog.SetLogLoggerLevel(slog.LevelInfo)
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if *privateKeyPath == "" || *help {
		fmt.Println("Usage: `sshreq -f [private_key] -i [interval]`")
		flagSet.PrintDefaults()
		os.Exit(0)
	}

	var token string
	token = viper.GetString("token")
	if token == "" {
		token, err = sshreq.RequestLogin()
		sshreq.ExitIf(err)
	}

	viper.Set("token", token)
	if err := viper.WriteConfig(); err != nil {
		panic(err.Error())
	}

	csr := sshreq.GenerateCsr(privateKeyPath, interval, viper.GetString("token"))
	csrString, err := json.Marshal(csr)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(string(csrString))
}
