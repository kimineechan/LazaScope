package view

import (
	"strings"
	"testing"

	"lazascope/internal/rules"
	"lazascope/internal/sample"
)

// The timeline holds what the made-up PC can date, newest first, with a
// program's copies as one moment, and keeps addresses out of the saved page.
func TestTimeline(t *testing.T) {
	s := sample.PC()
	b := Build(s, rules.Check(s))
	rows := b.Timeline.Rows
	if len(rows) == 0 {
		t.Fatal("the timeline is empty")
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].When.After(rows[i-1].When) {
			t.Fatalf("row %d is newer than the row above it", i)
		}
	}
	var all []string
	for _, row := range rows {
		all = append(all, strings.Join(row.Cells[1:], " | "))
	}
	text := strings.Join(all, "\n")
	for _, want := range []string{
		"Opened by this account | UserAssist | FabrikamLauncherSetup.exe",
		"Downloaded file is running | Download mark | FabrikamLauncherSetup.exe",
		"Defender found Trojan:Win32/Wacatac.B!ml | Defender's log",
		"Defender told to skip a place | Defender's log",
		"Hardware error | System log",
		"Blue screen | System log",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the timeline lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "Started | Running now | msedge.exe") > 0 && !strings.Contains(text, "msedge.exe (") {
		t.Error("the browser's copies are listed one by one")
	}
	// The download's address is shown in the window and kept out of the saved web page.
	for _, row := range rows {
		if row.Cells[1] != "Downloaded file is running" {
			continue
		}
		links := 0
		for _, line := range row.Detail {
			if strings.Contains(line.Text, "https://") && line.Style != Link {
				t.Errorf("an address is not marked as one: %q", line.Text)
			}
			if line.Style == Link {
				links++
			}
		}
		if links != 2 {
			t.Errorf("the download's addresses are missing from its details: %d", links)
		}
	}
}
