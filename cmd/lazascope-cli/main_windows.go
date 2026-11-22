//go:build windows

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
  lazascope-cli scan [--details] [--demo]   Take a full look and list what is worth a look, with the reasons
  lazascope-cli report <file> [--demo]      Take a full look and write the report (.html, .txt or .json)
  lazascope-cli startup [--details]         List everything set to start by itself
  lazascope-cli running [--details]         List the running programs as a family tree
  lazascope-cli network                     List the connections and the ports programs wait on
  lazascope-cli protection                  Show how the PC is protected and who can get into it
  lazascope-cli sign <file>...              Say who signed each file and whether the signature holds
  lazascope-cli rules                       List every rule and why it exists
  lazascope-cli version

Everything is read from this PC. Nothing is changed and nothing is sent anywhere.
With --demo a made-up PC is shown in place of this one.
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
	case "scan":
		err = scanAll(flags["--details"], flags["--demo"])
	case "report":
		err = saveReport(strings.Join(args, " "), flags["--demo"])
	case "startup":
		err = startupList(flags["--details"])
	case "running":
		err = runningList(flags["--details"])
	case "network":
		err = networkList()
	case "protection":
		err = protectionList()
	case "sign":
		err = sign(args)
	case "rules":
		ruleList(flags["--markdown"])
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

// cut shortens text to fit a column.
func cut(text string, width int) string {
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}
	return string(runes[:width-1]) + "~"
}
