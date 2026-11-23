//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"

	"lazascope/internal/view"
)

// The views of a list must never hide a finding, and the count beside them
// must say what is on show.
func TestViewsOfAList(t *testing.T) {
	rows := []view.Row{
		{Cells: []string{"Look first", "powershell.exe"}, Level: view.First, Windows: true}, // a flagged part of Windows
		{Cells: []string{"Worth a look", "tool.exe"}, Level: view.Look},
		{Cells: []string{"Good to know", "old.exe"}, Level: view.Info},
		{Cells: []string{"", "notes.exe"}},
		{Cells: []string{"", "svchost.exe"}, Windows: true},
		{Cells: []string{"Off", "game.exe"}, Off: true},
		{Cells: []string{"OK", "Firewall"}, Level: view.Fine},
	}
	keep := func(want func(view.Row) bool) (shown []view.Row) {
		for _, row := range rows {
			if want(row) {
				shown = append(shown, row)
			}
		}
		return shown
	}
	if got := len(keep(everything)); got != len(rows) {
		t.Errorf("everything keeps %d of %d rows", got, len(rows))
	}
	// What is worth a look: the three grades of finding, and nothing else.
	if got := keep(flagged); len(got) != 3 || got[0].Level != view.First || got[1].Level != view.Look || got[2].Level != view.Info {
		t.Errorf("only what is worth a look keeps %d rows: %+v", len(got), got)
	}
	// Not part of Windows: everything from other makers, and the flagged part
	// of Windows too, because a view must not hide a finding.
	other := keep(notWindows)
	if len(other) != 6 || other[0].Cells[1] != "powershell.exe" {
		t.Fatalf("not part of Windows keeps %d rows, the first %q", len(other), other[0].Cells)
	}
	for _, row := range other {
		if row.Cells[1] == "svchost.exe" {
			t.Error("an unflagged part of Windows was kept")
		}
	}

	// The count says so when a part of Windows is among them.
	for _, test := range []struct {
		shown []view.Row
		name  string
		want  string
	}{
		{other, notWindowsName, "6 of 7 shown. 1 flagged part of Windows."},
		{append(append([]view.Row{}, other...), rows[0]), notWindowsName, "7 of 7 shown. 2 flagged parts of Windows."},
		{other[1:], notWindowsName, "5 of 7 shown."},
		{other, "Only what is worth a look", "6 of 7 shown."}, // any other view counts and no more
		{nil, notWindowsName, "0 of 7 shown."},
	} {
		if got := kept(test.shown, len(rows), test.name); got != test.want {
			t.Errorf("%s with %d rows: got %q, want %q", test.name, len(test.shown), got, test.want)
		}
	}
}

func TestSentence(t *testing.T) {
	for give, want := range map[string]string{
		"the name of the report must end in .html, .txt or .json": "The name of the report must end in .html, .txt or .json.",
		"Access is denied.": "Access is denied.",
		"":                  "Unknown error.",
	} {
		if got := sentence(errors.New(give)); got != want {
			t.Errorf("sentence(%q) = %q, want %q", give, got, want)
		}
	}
}

// The colour of a row's first cell follows what the rules said of it.
func TestTint(t *testing.T) {
	if tint(view.Row{Level: view.First}) == tint(view.Row{Level: view.Look}) || tint(view.Row{Level: view.Look}) == tint(view.Row{Level: view.Fine}) {
		t.Error("two grades share a colour")
	}
	if tint(view.Row{}) != 0 {
		t.Error("a plain row is tinted")
	}
	if tint(view.Row{Off: true}) == 0 {
		t.Error("a row that is switched off is not greyed")
	}
}

func TestLookupAddress(t *testing.T) {
	const print = "da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b"
	address, ok := lookupAddress(print)
	if !ok || address != "https://www.virustotal.com/gui/file/"+print {
		t.Errorf("got %q, %v", address, ok)
	}
	// Nothing but a fingerprint can become part of the address.
	for _, bad := range []string{"", "abc", strings.ToUpper(print), print + "0", print[:63] + "g", print[:60] + "/../", print[:62] + "?x", strings.Repeat(" ", 64)} {
		if address, ok := lookupAddress(bad); ok || address != "" {
			t.Errorf("%q was made into the address %q", bad, address)
		}
	}
}

// A fingerprint worked out after the look is added to the details of the
// row it belongs to, once, and to no other row.
func TestWithPrint(t *testing.T) {
	const print = "da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b"
	l := &list{prints: map[string]string{`c:\tools\thing.exe`: print}}
	row := view.Row{Path: `C:\Tools\Thing.exe`, Detail: []view.Line{{Style: view.Heading, Text: "Thing"}}}
	got := l.withPrint(row)
	if len(got) != 4 || got[2].Text != print || got[2].Style != view.Command || len(row.Detail) != 1 {
		t.Errorf("the details became %+v, and the row's own are now %d lines", got, len(row.Detail))
	}
	// The look had it already: it is not said twice.
	row.Detail = append(row.Detail, view.Line{Style: view.Command, Text: print})
	if got := l.withPrint(row); len(got) != 2 {
		t.Errorf("a fingerprint already shown was added again: %d lines", len(got))
	}
	for _, other := range []view.Row{{Path: `C:\Tools\other.exe`, Detail: row.Detail[:1]}, {Detail: row.Detail[:1]}} {
		if got := l.withPrint(other); len(got) != 1 {
			t.Errorf("the row for %q was given a fingerprint", other.Path)
		}
	}
}
