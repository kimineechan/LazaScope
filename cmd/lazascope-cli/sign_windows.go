//go:build windows

package main

import (
	"fmt"
	"time"

	"lazascope/internal/sigcheck"
)

// sign prints the signature of each file named.
func sign(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("name at least one file to check")
	}
	checker := sigcheck.New()
	defer checker.Close()
	for _, path := range files {
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
	}
	return nil
}
