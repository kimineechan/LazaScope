package view

import (
	"strings"
	"testing"

	"lazascope/internal/model"
	"lazascope/internal/sigcheck"
)

// A script that starts by itself is shown with what its text says it does,
// and with how it begins.
func TestScriptIsRead(t *testing.T) {
	s := pc()
	read := model.File{Path: `C:\Users\sam\Scripts\tidy.ps1`, Exists: true, Script: &model.Script{
		Lines: []string{"# Tidies the Downloads folder", "Remove-Item $env:USERPROFILE\\Downloads\\*.tmp"}, More: true,
		Signs: []string{"It fetches something from the internet.", "It deletes files or folders."}}}
	quiet := model.File{Path: `C:\Users\sam\Scripts\hello.cmd`, Exists: true, Script: &model.Script{Lines: []string{"@echo hello"}}}
	unread := model.File{Path: `C:\Users\sam\Scripts\huge.js`, Exists: true}
	scrambled := model.File{Path: `C:\Users\sam\Scripts\odd.vbe`, Exists: true}
	for name, file := range map[string]model.File{"Tidy": read, "Hello": quiet, "Huge": unread, "Odd": scrambled} {
		s.Startup = append(s.Startup, entry(model.RunKey, name, file))
	}
	page := build(s).Startup

	row := find(t, page, "Tidy")
	said := words(row.Detail)
	for _, want := range []string{
		"What the script does, going by its text", "It fetches something from the internet.", "It deletes files or folders.",
		"This is a reading of the text, not a test: nothing was run.", "How it begins", "# Tidies the Downloads folder", "The script goes on.",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the detail of a script that was read lacks %q:\n%s", want, said)
		}
	}
	// The script's own lines are marked, so that a saved report can leave them out.
	marked := 0
	for _, line := range row.Detail {
		if line.Style == Excerpt {
			marked++
			if !strings.Contains(line.Text, "Tidies") && !strings.Contains(line.Text, "Remove-Item") {
				t.Errorf("a line that is not the script's own is marked as one: %q", line.Text)
			}
		} else if strings.Contains(line.Text, "Remove-Item") {
			t.Errorf("a line of the script is not marked as one: %q", line.Text)
		}
	}
	if marked != 2 {
		t.Errorf("%d lines are marked as the script's own, want 2", marked)
	}
	if row.Cells[3] != "Script file" {
		t.Errorf("the maker of a script is shown as %q", row.Cells[3])
	}

	said = words(find(t, page, "Hello").Detail)
	if !strings.Contains(said, "LazaScope read it and saw none of the things it looks for") || strings.Contains(said, "The script goes on.") {
		t.Errorf("a script with nothing to remark on:\n%s", said)
	}
	said = words(find(t, page, "Huge").Detail)
	if !strings.Contains(said, "LazaScope did not read this script") || strings.Contains(said, "How it begins") {
		t.Errorf("a script that was not read:\n%s", said)
	}
	said = words(find(t, page, "Odd").Detail)
	if !strings.Contains(said, "saved in a scrambled form, so LazaScope could not read what it says") {
		t.Errorf("a scrambled script:\n%s", said)
	}

	// What the script does is also among the facts of its finding.
	worth := words(find(t, build(s).Worth, "Tidy").Detail)
	if !strings.Contains(worth, "Going by the script's text: It fetches something from the internet. It deletes files or folders.") {
		t.Errorf("the finding does not say what the script does:\n%s", worth)
	}
}

// The fingerprint the look worked out for a flagged file is shown with the
// file, in its own list and under Worth a look.
func TestFingerprintIsShown(t *testing.T) {
	const print = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	s := pc()
	tool := model.File{Path: `C:\Program Files\Tool\tool.exe`, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Unsigned}}
	s.Startup = append(s.Startup, entry(model.RunKey, "Tool", tool))
	s.Fingerprints = map[string]string{`c:\program files\tool\tool.exe`: print}
	book := build(s)
	for name, page := range map[string]Page{"Start-up": book.Startup, "Worth a look": book.Worth} {
		said := words(find(t, page, "Tool").Detail)
		if !strings.Contains(said, "SHA-256):\n"+print) {
			t.Errorf("the %s page does not show the fingerprint:\n%s", name, said)
		}
	}
	if said := words(find(t, book.Worth, "Tool").Detail); !strings.Contains(said, "A fingerprint is a long number worked out from every byte of a file.") {
		t.Errorf("the term is not explained where it first appears:\n%s", said)
	}
	if said := words(find(t, book.Startup, "Notes").Detail); strings.Contains(said, "SHA-256") {
		t.Errorf("a file with no fingerprint is shown with one:\n%s", said)
	}
}
