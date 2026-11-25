//go:build windows

package history

import (
	"os"
	"testing"

	"lazascope/internal/model"
)

// TestLive reads this PC's records. It runs only when LAZASCOPE_LIVE=1.
func TestLive(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") != "1" {
		t.Skip("set LAZASCOPE_LIVE=1 to read this PC's records")
	}
	home, _ := os.UserHomeDir()
	runs, gaps := Collect(model.Folders{Profile: home, ProgramFiles: os.Getenv("ProgramFiles"), ProgramFilesX86: os.Getenv("ProgramFiles(x86)"),
		Windows: os.Getenv("SystemRoot"), System: os.Getenv("SystemRoot") + `\System32`, Downloads: home + `\Downloads`}, false)
	users, bams := 0, 0
	for _, r := range runs {
		switch r.Source {
		case "UserAssist":
			users++
		case "BAM":
			bams++
		}
	}
	t.Logf("%d UserAssist records, %d BAM records, gaps: %v", users, bams, gaps)
	if users == 0 {
		t.Error("no UserAssist record was read")
	}
	for i := 1; i < len(runs); i++ {
		if runs[i].Last.After(runs[i-1].Last) {
			t.Fatal("the records are not newest first")
		}
	}
}
