//go:build windows

package main

import (
	"errors"
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
		{other, notWindowsName, "6 of 7 shown. 1 is a flagged part of Windows."},
		{append(append([]view.Row{}, other...), rows[0]), notWindowsName, "7 of 7 shown. 2 are flagged parts of Windows."},
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
