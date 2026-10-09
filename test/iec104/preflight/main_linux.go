//go:build linux

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fatal(fmt.Errorf("usage: preflight firewall|client|server|ctl"))
	}
	var err error
	switch os.Args[1] {
	case "firewall":
		err = runFirewall()
	case "client", "server":
		err = runEndpoint(os.Args[1])
	case "ctl":
		err = runControlCLI(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
