//go:build windows

package main

import (
	"errors"
	"fmt"
	"lazascope/internal/i18n"
	"runtime"
	"strings"
	"time"

	"lazascope/internal/clipboard"
	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
)

// walletList prints the cryptocurrency wallets on this PC and what the
// cryptocurrency rules found.
func walletList(demo bool) error {
	var s *model.Snapshot
	var findings []rules.Finding
	if demo {
		s = sample.PC()
		findings = rules.Check(s)
	} else {
		s = scan.Run(scan.Everything, progress)
		findings = scan.Judge(s)
	}
	b := view.Build(s, findings)
	fmt.Printf("%s\n\n", strings.ToUpper(b.Wallets.Title))
	for _, row := range b.Wallets.Rows {
		check := row.Cells[0]
		if check == "" {
			check = "-"
		}
		fmt.Printf("  %-13s %-28s %-26s %s\n", check, cut(row.Cells[1], 28), cut(row.Cells[2], 26), row.Cells[3])
	}
	crypto := rules.Crypto()
	shown := 0
	for _, f := range findings {
		if !crypto[f.Rule] {
			continue
		}
		if shown == 0 {
			fmt.Println("\nWorth a look:")
		}
		shown++
		fmt.Printf("\n[%s] %s\n    %s  (rule %s)\n    Why:  %s\n    Do:   %s\n", f.Severity, f.Title, f.Subject, f.Rule, f.Reason, f.Advice)
	}
	if shown == 0 {
		fmt.Println("\nNothing on the cryptocurrency side stood out to the rules.")
	}
	return nil
}

// swapTest runs the address-swap test from a terminal.
func swapTest() error {
	// The window and the test share one thread, so that the test can answer
	// the window's messages while it waits.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	window, done, err := clipboard.Window()
	if err != nil {
		return fmt.Errorf(i18n.T("no window could be made to own the clipboard: %w"), err)
	}
	defer done()
	fmt.Println(i18n.T("Copying three made-up wallet addresses, one at a time, and watching for two seconds each."))
	fmt.Println(i18n.T("They have broken checksums, so no wallet accepts them, and are kept out of the clipboard history."))
	result, err := clipboard.Test(window, 2*time.Second)
	restored := true
	if errors.Is(err, clipboard.ErrNotRestored) {
		restored, err = false, nil
		defer fmt.Println(i18n.T("The clipboard could not be put back as it was: copy again whatever you need."))
	}
	if err != nil {
		return err
	}
	if !result.Swapped {
		back := " The clipboard's text is back as it was."
		if !restored {
			back = ""
		}
		fmt.Printf("No program swapped any of them (%s).%s\n", strings.Join(result.Tried, ", "), back)
		return nil
	}
	fmt.Printf("A program swapped the made-up %s address for another: %s\n", result.Kind, result.Into)
	if result.PID != 0 {
		name := ""
		for _, p := range scan.Run(scan.Parts{Processes: true}, nil).Processes {
			if p.PID == result.PID {
				name = p.Name + " (" + p.File.Path + ")"
			}
		}
		fmt.Printf("Windows says the clipboard was last changed by process %d %s\n", result.PID, name)
	}
	fmt.Println(i18n.T("Do not send coins from this PC until it is cleaned. Scan it with your antivirus."))
	return nil
}
