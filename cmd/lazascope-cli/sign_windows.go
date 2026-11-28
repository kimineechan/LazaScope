//go:build windows

package main

import (
	"fmt"
	"lazascope/internal/files"
	"lazascope/internal/i18n"
	"time"

	"lazascope/internal/sigcheck"
)

// sign prints the signature of each file named.
func sign(paths []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("%s", i18n.T("name at least one file to check"))
	}
	checker := sigcheck.New()
	defer checker.Close()
	for _, path := range paths {
		start := time.Now()
		r := checker.Check(path)
		fmt.Printf("%s\n    %s", path, r.Status)
		if r.Signer != "" {
			fmt.Printf(" by %s", r.Signer)
		}
		if r.Source != sigcheck.NoSource {
			fmt.Printf(", %s", r.Source)
		}
		if r.Catalogue != "" {
			fmt.Printf(" (%s)", r.Catalogue)
		}
		fmt.Printf("  [%d ms]\n", time.Since(start).Milliseconds())
		if r.Problem != "" {
			fmt.Printf("    %s", r.Problem)
			if r.Code != 0 {
				fmt.Printf(" (0x%08X)", r.Code)
			}
			fmt.Println()
		}
		// The fingerprint tells this file from every other, whatever it is called.
		if print, err := files.Fingerprint(path); err == nil {
			fmt.Printf("    SHA-256 %s\n", print)
		}
	}
	return nil
}
