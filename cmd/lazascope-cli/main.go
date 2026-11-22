// lazascope-cli prints what LazaScope finds on this PC, for a terminal or a
// script. It reads the same things the window shows and changes nothing.
package main

import (
	"fmt"
	"os"
	"strings"

	"lazascope"
)

const usage = `LazaScope command-line tool

Usage:
  lazascope-cli sign <file>...     Say who signed each file and whether the signature holds
  lazascope-cli version

Everything is read from this PC. Nothing is changed and nothing is sent anywhere.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	flags := map[string]bool{}
	var args []string
	for _, a := range os.Args[2:] {
		if strings.HasPrefix(a, "--") {
			flags[a] = true
		} else {
			args = append(args, a)
		}
	}
	var err error
	switch os.Args[1] {
	case "sign":
		err = sign(args)
	case "version", "--version":
		fmt.Println("LazaScope", lazascope.Version())
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lazascope-cli:", err)
		os.Exit(1)
	}
}
