package view

import (
	"strings"
	"testing"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
)

// row finds a row of the Wallets page by its name.
func walletRow(t *testing.T, b *Book, name string) Row {
	t.Helper()
	for _, row := range b.Wallets.Rows {
		if row.Cells[1] == name {
			return row
		}
	}
	t.Fatalf("the Wallets page has no row %q", name)
	return Row{}
}

func detailOf(row Row) string {
	var lines []string
	for _, line := range row.Detail {
		lines = append(lines, line.Text)
	}
	return strings.Join(lines, "\n")
}

// Before the search, the page says it has not run; after it, each file is
// a row with its level and plain advice, and the search says what it read.
func TestPhraseRows(t *testing.T) {
	s := sample.PC()
	b := Build(s, rules.Check(s))
	before := walletRow(t, b, "Recovery phrases in files")
	if before.Level != Unknown || !strings.Contains(before.Cells[3], "Not searched") || before.Cells[2] != "Search" {
		t.Errorf("before the search: %v %q", before.Level, before.Cells)
	}

	s.Phrases = sample.Phrases()
	b = Build(s, rules.Check(s))
	found := walletRow(t, b, "Recovery phrase")
	if found.Level != First || found.Cells[2] != "Written in a file, copied by OneDrive" || !strings.HasSuffix(found.Cells[3], `wallet backup.txt, line 3`) {
		t.Errorf("the phrase: %v %q", found.Level, found.Cells)
	}
	text := detailOf(found)
	for _, want := range []string{"Line 3 of this file starts 12 of them in a row", "complete 12-word phrase", "one time in 16", "move the coins", "empty the Recycle Bin",
		"OneDrive copies this file off the PC", "did not show, keep or send the words"} {
		if !strings.Contains(text, want) {
			t.Errorf("the phrase's details lack %q:\n%s", want, text)
		}
	}
	words := walletRow(t, b, "Recovery words")
	if words.Level != Look || !strings.Contains(detailOf(words), "do not hold a complete phrase") {
		t.Errorf("the run of words: %v\n%s", words.Level, detailOf(words))
	}
	list := walletRow(t, b, "Recovery word list")
	if list.Level != Plain || list.Cells[0] != "" || strings.Contains(detailOf(list), "What to do") {
		t.Errorf("the word list: %v %q\n%s", list.Level, list.Cells, detailOf(list))
	}
	after := walletRow(t, b, "Recovery phrases in files")
	if after.Level != First || after.Cells[3] != "Found a recovery phrase in 1 file, and recovery words in 1 more" {
		t.Errorf("after the search: %v %q", after.Level, after.Cells)
	}
	if text := detailOf(after); !strings.Contains(text, "1,873 files read") || !strings.Contains(text, "41 files kept only in the cloud") || !strings.Contains(text, "2 files larger than 4 MB") {
		t.Errorf("the search's details:\n%s", text)
	}
	// The search and the analyst's evidence find the rows.
	if got := found.Fields["kind"]; len(got) == 0 || got[len(got)-1] != "recovery phrase" {
		t.Errorf("the phrase row's kinds: %q", got)
	}

	// A search with nothing found is good news, unless it was cut short.
	s.Phrases = &model.PhraseSearch{Read: 12480, Folders: []string{`C:\Users\sam\Desktop`}}
	b = Build(s, rules.Check(s))
	if row := walletRow(t, b, "Recovery phrases in files"); row.Level != Fine || !strings.HasPrefix(row.Cells[3], "Searched 12,480 files at ") {
		t.Errorf("nothing found: %v %q", row.Level, row.Cells)
	}
	s.Phrases.Stopped = true
	b = Build(s, rules.Check(s))
	if row := walletRow(t, b, "Recovery phrases in files"); row.Level != Unknown || !strings.HasSuffix(row.Cells[3], "(stopped before the end)") {
		t.Errorf("a stopped search: %v %q", row.Level, row.Cells)
	}
}

func TestPlaces(t *testing.T) {
	for want, f := range map[string]model.PhraseFile{
		"line 4":                         {Path: `a.txt`, Runs: 1, Lines: []int{4}},
		"paragraph 2":                    {Path: `a.DOCX`, Runs: 1, Lines: []int{2}},
		"lines 4 and 9":                  {Path: `a.md`, Runs: 2, Lines: []int{4, 9}},
		"lines 1, 2 and 3":               {Path: `a.md`, Runs: 3, Lines: []int{1, 2, 3}},
		"lines 1, 2, 3, 4, 5 and others": {Path: `notes`, Runs: 30, Lines: []int{1, 2, 3, 4, 5, 6, 7}},
	} {
		if got := places(f); got != want {
			t.Errorf("places(%v) = %q, want %q", f, got, want)
		}
	}
	if got := several(12480, "file", "files"); got != "12,480 files" {
		t.Errorf("several = %q", got)
	}
}
