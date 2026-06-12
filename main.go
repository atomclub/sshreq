package main

// `sshreq` is an internal tool used to generate a CSR.

// Usage:
// 	sshreq -f [private_key] -i [interval]

import (
	"fmt"
	"log/slog"
	"os"

	flag "github.com/spf13/pflag"
)

func ExitIf(err error) {
	if err != nil {
		slog.Any("error", err.Error())
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
	ExitIf(err)

	slog.SetLogLoggerLevel(slog.LevelInfo)
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if *privateKeyPath == "" || *help {
		fmt.Println("Usage: sshreq -f [private_key] -i [interval]")
		flags.PrintDefaults()
		os.Exit(0)
	}

	fmt.Println(run(privateKeyPath, interval))
}
