//go:build windows

package main

import (
	"errors"
	"fmt"
	"lazascope/internal/i18n"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lazascope/internal/phrase"
	"lazascope/internal/wallets"
)

// phraseSearch looks for recovery phrases written in files, in the folders
// named or else in the ones where people keep notes, and prints where they
// are. The words themselves are never printed or kept.
func phraseSearch(folders []string) error {
	if len(folders) == 0 {
		folders = phrase.Places()
		if len(folders) == 0 {
			return errors.New(i18n.T("Windows did not say where this account's Desktop, Documents and Downloads folders are, so there is nowhere to search"))
		}
	}
	for i, folder := range folders {
		if abs, err := filepath.Abs(folder); err == nil {
			folders[i] = abs
		}
		if info, err := os.Stat(folders[i]); err != nil || !info.IsDir() {
			return fmt.Errorf("%s is not a folder that can be opened", folder)
		}
	}
	fmt.Println(i18n.T("Searching for recovery phrases in:"))
	for _, folder := range folders {
		fmt.Println("  " + folder)
	}
	fmt.Println(i18n.T("Only where they are is noted. The words are never shown, kept or sent."))
	noted := false
	result := phrase.Search(folders, nil, func(read int) {
		noted = true
		fmt.Fprintf(os.Stderr, "  %d files read...\r", read)
	})
	if noted {
		fmt.Fprint(os.Stderr, "                              \r")
	}

	fmt.Printf("\nRead %d files.", result.Read)
	var unread []string
	if result.Cloud > 0 {
		unread = append(unread, fmt.Sprintf("%d kept only in the cloud, as reading them would download them", result.Cloud))
	}
	if result.Big > 0 {
		unread = append(unread, fmt.Sprintf("%d larger than %d MB", result.Big, phrase.Most>>20))
	}
	if result.Locked > 0 {
		unread = append(unread, fmt.Sprintf("%d files or folders that could not be opened", result.Locked))
	}
	if len(unread) > 0 {
		fmt.Printf(" Not read: %s.", strings.Join(unread, "; "))
	}
	fmt.Println()
	if result.Full {
		fmt.Printf("The search stops after %d files and stopped there, so some files were not read.\n", phrase.Limit)
	}
	if len(result.Found) == 0 {
		fmt.Println("\nNo recovery phrase was found. A phrase can still hide where this search does not look: in a photo or a screenshot, a PDF, an email, a password manager, or written in another language.")
		return nil
	}
	clouds := wallets.Clouds()
	phrases := 0
	fmt.Println()
	for _, f := range result.Found {
		var lines []string
		for _, line := range f.Lines {
			lines = append(lines, strconv.Itoa(line))
		}
		at := phrase.Unit(f.Path) + " " + strings.Join(lines, ", ")
		if len(lines) > 1 {
			at = phrase.Unit(f.Path) + "s " + strings.Join(lines, ", ")
		}
		label, about := "LOOK", fmt.Sprintf("%s: %d recovery words in a row, not confirmed as a phrase", at, f.Words)
		switch {
		case f.List:
			label, about = "LIST", i18n.T("the recovery word list itself, in its own order: not a phrase")
		case f.Phrase > 0 && f.Electrum:
			phrases++
			label, about = "FIRST", fmt.Sprintf("%s: a complete %d-word Electrum seed whose check holds", at, f.Phrase)
		case f.Phrase > 0:
			phrases++
			label, about = "FIRST", fmt.Sprintf("%s: a complete %d-word recovery phrase whose check holds", at, f.Phrase)
		case f.Named:
			phrases++
			label, about = "FIRST", fmt.Sprintf("%s: %d recovery words in a row, in a file whose name points to a phrase", at, f.Words)
		}
		if synced := wallets.Synced(f.Path, clouds); synced != "" && !f.List {
			about += "; " + synced + " copies this file off the PC"
		}
		fmt.Printf("%-6s %s\n       %s\n", label, f.Path, about)
	}
	if phrases > 0 {
		fmt.Println("\nWhoever has a phrase has the wallet's coins. If a phrase belongs to a wallet that holds coins, make a new wallet on a device you trust,")
		fmt.Println(i18n.T("move the coins into it, and only then delete the file and empty the Recycle Bin. A test phrase that never held coins needs nothing moved."))
	}
	return nil
}
