package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	name := strings.ToLower(filepath.Base(os.Args[0]))
	subcommand := "ar"
	if strings.Contains(name, "ranlib") {
		subcommand = "ranlib"
	}
	zig := os.Getenv("ZIG")
	if zig == "" {
		zig = "zig"
	}
	args := append([]string{subcommand}, os.Args[1:]...)
	cmd := exec.Command(zig, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}
