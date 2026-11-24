//go:build windows

// lazascope-cli prints what LazaScope finds on this PC, for a terminal or a
// script. It reads the same things the window shows and changes nothing.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"strings"

	"lazascope"
	"lazascope/internal/view"
)

const usage = `LazaScope command-line tool

Usage:
  lazascope-cli scan [--details] [--demo]   Take a full look and list what is worth a look, with the reasons
  lazascope-cli report <file> [--demo]      Take a full look and write the report (.html, .txt or .json)
  lazascope-cli startup [--details]         List everything set to start by itself
  lazascope-cli running [--details]         List the running programs as a family tree
  lazascope-cli network                     List the connections and the ports programs wait on
  lazascope-cli protection                  Show how the PC is protected and who can get into it
  lazascope-cli health                      Show hardware errors, crashes and disk trouble from Windows' own log
  lazascope-cli compare <report.json>       Take a look and say what has changed since a report saved as data
  lazascope-cli watch [seconds]             Keep looking for a while (60 seconds unless told) and list what came and went
  lazascope-cli sign <file>...              Say who signed each file and whether the signature holds
  lazascope-cli virustotal [file]...        Ask VirusTotal about files by fingerprint, or with none named about the
                                            programs that start or run (needs your own VirusTotal key)
  lazascope-cli rules [--markdown]          List every rule and why it exists (--markdown: as the table in docs/RULES.md)
  lazascope-cli wallets [--demo]            List the cryptocurrency wallets on this PC and what stood out about them
  lazascope-cli timeline [days] [--demo]    List what happened when, newest first (the last 7 days unless told)
  lazascope-cli protections [--demo]        List the protections this PC already has, whether each is on, and its backups
  lazascope-cli devices [--demo]            List which programs used the camera and the microphone, and when
  lazascope-cli live [seconds]              Watch programs start, live, and check each against the detections (60 seconds unless told)
  lazascope-cli detections [--markdown]     List every detection the live watch uses (--markdown: as the table in docs/DETECTIONS.md)
  lazascope-cli swap-test                   Copy made-up wallet addresses for a few seconds and watch whether a program swaps them
  lazascope-cli phrases [folder]...         Look for recovery phrases written in files (in Desktop, Documents and Downloads
                                            unless told), and say where they are without ever showing the words
  lazascope-cli find <search> [--details]   List the rows of every list that match a search, as in the window's
                                            search box (find ? explains how; --details: with the exact evidence)
  lazascope-cli attack <file.json>          Write a layer for MITRE's ATT&CK Navigator of what a look finds
                                            (--coverage: of what the rules look for; --demo: of the made-up PC)
  lazascope-cli version
  lazascope-cli help

Everything is read from this PC. Nothing is changed, and nothing is sent anywhere
except the fingerprints the virustotal command sends, with your key.
With --demo a made-up PC is shown in place of this one.
`

// commands lists what each command takes: its options, and whether it is
// given file names.
var commands = map[string]struct {
	options []string
	files   bool
}{
	"scan": {options: []string{"--details", "--demo"}}, "report": {options: []string{"--demo"}, files: true},
	"startup": {options: []string{"--details"}}, "running": {options: []string{"--details"}},
	"network": {}, "protection": {}, "health": {}, "compare": {files: true}, "watch": {files: true}, "sign": {files: true}, "rules": {options: []string{"--markdown"}}, "version": {},
	"attack": {options: []string{"--coverage", "--demo"}, files: true}, "virustotal": {files: true},
	"find":    {options: []string{"--details", "--demo"}, files: true},
	"wallets": {options: []string{"--demo"}}, "swap-test": {}, "timeline": {options: []string{"--demo"}, files: true},
	"protections": {options: []string{"--demo"}}, "devices": {options: []string{"--demo"}},
	"live": {files: true}, "detections": {options: []string{"--markdown"}}, "phrases": {files: true},
}

func main() {
	// A fault of the tool's own must end in words, and say that nothing on
	// the PC was touched.
	defer func() {
		if fault := recover(); fault != nil {
			fmt.Fprintf(os.Stderr, "lazascope-cli stopped on an error of its own: %v\nNothing on this PC was changed. Please report this, with the lines below.\n\n%s", fault, debug.Stack())
			os.Exit(3)
		}
	}()
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	command := os.Args[1]
	switch command {
	case "help", "--help", "-h", "/?":
		fmt.Print(usage)
		return
	case "--version":
		command = "version"
	}
	takes, known := commands[command]
	if !known {
		fmt.Fprintf(os.Stderr, "lazascope-cli: there is no command %q.\n\n%s", command, usage)
		os.Exit(2)
	}
	flags := map[string]bool{}
	var args []string
	for _, a := range os.Args[2:] {
		switch {
		case !strings.HasPrefix(a, "--"):
			args = append(args, a)
		case slices.Contains(takes.options, a):
			flags[a] = true
		default:
			fmt.Fprintf(os.Stderr, "lazascope-cli: %s does not take the option %s. Run \"lazascope-cli help\" for the list.\n", command, a)
			os.Exit(2)
		}
	}
	if len(args) > 0 && !takes.files {
		fmt.Fprintf(os.Stderr, "lazascope-cli: %s takes no file name, and was given %q. Run \"lazascope-cli help\" for the list.\n", command, args[0])
		os.Exit(2)
	}
	var err error
	switch command {
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
	case "health":
		err = healthList()
	case "compare":
		err = compareWith(strings.Join(args, " "))
	case "watch":
		err = watchFor(strings.Join(args, " "))
	case "sign":
		err = sign(args)
	case "rules":
		ruleList(flags["--markdown"])
	case "attack":
		err = attackLayer(strings.Join(args, " "), flags["--coverage"], flags["--demo"])
	case "virustotal":
		err = virusTotalCommand(args)
	case "find":
		err = find(strings.Join(args, " "), flags["--details"], flags["--demo"])
	case "wallets":
		err = walletList(flags["--demo"])
	case "timeline":
		err = timelineList(strings.Join(args, " "), flags["--demo"])
	case "live":
		err = liveWatch(strings.Join(args, " "))
	case "detections":
		detectionList(flags["--markdown"])
	case "protections":
		err = printPage(func(b *view.Book) *view.Page { return &b.Defences }, flags["--demo"])
	case "devices":
		err = printPage(func(b *view.Book) *view.Page { return &b.Devices }, flags["--demo"])
	case "swap-test":
		err = swapTest()
	case "phrases":
		err = phraseSearch(args)
	case "version":
		fmt.Println("LazaScope", lazascope.Version())
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
