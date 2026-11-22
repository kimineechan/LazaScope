// Package view lays a look at a PC out as pages for a person to read: what
// goes in each row of each list, and what is said about a row when it is
// chosen.
//
// The window and the report both show these pages, so every word is
// written once, here. The package knows nothing about windows or files. It
// only arranges facts.
package view

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/rules"
)

// Level is how much attention a row deserves. It colours the row's first
// cell.
type Level int

const (
	Plain   Level = iota // nothing to say about it
	Fine                 // checked, and as it should be
	Info                 // good to know
	Look                 // worth a look
	First                // look at this first
	Unknown              // could not be read
)

func (l Level) String() string {
	switch l {
	case Fine:
		return "OK"
	case Info:
		return "Good to know"
	case Look:
		return "Worth a look"
	case First:
		return "Look first"
	case Unknown:
		return "Not known"
	}
	return ""
}

// level turns the severity of a finding into the level of its row.
func level(severity rules.Severity) Level {
	switch severity {
	case rules.High:
		return First
	case rules.Medium:
		return Look
	}
	return Info
}

// Style is how a line of detail is lettered.
type Style int

const (
	Text    Style = iota // ordinary text
	Heading              // a small heading
	Aside                // a note, smaller and quieter
	Command              // a command or a path, in letters of one width
)

// Line is one line of what is said about a row.
type Line struct {
	Style Style
	Text  string
}

// Row is one row of a list.
type Row struct {
	Cells   []string
	Level   Level
	Detail  []Line
	Path    string // the file the row is about, to show in its folder
	Windows bool   // it is a part of Windows itself
	Off     bool   // it is switched off
}

// Column is one column of a list.
type Column struct {
	Title string
	Width int // in the units of the window's layout; the last column takes what is left
}

// Page is one list with its heading.
type Page struct {
	Name    string // a short name, for a tab or a link
	Title   string
	Intro   string
	Columns []Column
	Rows    []Row
	Unseen  []string // what could not be read
}

// Count returns how many rows of a page are worth a look or more.
func (p Page) Count() int {
	n := 0
	for _, row := range p.Rows {
		if row.Level == Look || row.Level == First {
			n++
		}
	}
	return n
}

// Glance is one of the five lights of the overview, with its words.
type Glance struct {
	Area    model.Area
	Light   rules.Light
	Verdict string // such as "2 worth a look"
	Facts   string // such as "Antivirus on. Firewall on."
}

// Book is a whole look at a PC, laid out.
type Book struct {
	Snapshot *model.Snapshot
	Findings []rules.Finding
	Summary  string // which PC, when, and with what rights
	Glances  [model.Areas]Glance

	Protection, Startup, Running, Connections, Accounts, Worth Page
}

// Pages returns the six lists in the order they are shown.
func (b *Book) Pages() []*Page {
	return []*Page{&b.Protection, &b.Startup, &b.Running, &b.Connections, &b.Accounts, &b.Worth}
}

// builder holds what the pages are made from.
type builder struct {
	s        *model.Snapshot
	findings []rules.Finding
	byRef    map[string][]rules.Finding
}

// Build lays out a snapshot and the findings the rules made of it.
func Build(s *model.Snapshot, findings []rules.Finding) *Book {
	b := &builder{s: s, findings: findings, byRef: map[string][]rules.Finding{}}
	for _, f := range findings {
		b.byRef[f.Ref] = append(b.byRef[f.Ref], f)
	}
	book := &Book{Snapshot: s, Findings: findings, Summary: summary(s)}
	book.Protection = b.protection()
	book.Startup = b.startup()
	book.Running = b.running()
	book.Connections = b.connections()
	book.Accounts = b.accounts()
	book.Worth = b.worth()
	lights := rules.Lights(s, findings)
	for area := model.Protection; area < model.Areas; area++ {
		book.Glances[area] = Glance{Area: area, Light: lights[area], Verdict: verdict(lights[area], findings, area), Facts: b.facts(area)}
	}
	return book
}

// summary says which PC was looked at, when, and with what rights.
func summary(s *model.Snapshot) string {
	rights := "without administrator rights, so some details could not be read"
	if s.Elevated {
		rights = "with administrator rights"
	}
	text := strings.TrimSpace(s.Computer)
	if s.Windows != "" {
		text += ", " + s.Windows
	}
	if !s.Taken.IsZero() {
		text += ". Looked at on " + s.Taken.Format("2 January 2006") + " at " + s.Taken.Format("15:04")
	}
	if s.User != "" {
		text += " as " + s.User
	}
	return strings.TrimLeft(text+", "+rights+".", ", ")
}

// verdict puts a light into words with its counts.
func verdict(light rules.Light, findings []rules.Finding, area model.Area) string {
	high, medium, low := rules.Count(findings, area)
	var parts []string
	if high > 0 {
		parts = append(parts, strconv.Itoa(high)+" to look at first")
	}
	if medium > 0 {
		parts = append(parts, strconv.Itoa(medium)+" worth a look")
	}
	if low > 0 {
		parts = append(parts, strconv.Itoa(low)+" good to know")
	}
	switch {
	case light == rules.Grey:
		return "Could not be read"
	case high == 0 && medium == 0 && low == 0:
		return "Nothing stands out"
	case high == 0 && medium == 0:
		return "Nothing stands out (" + parts[0] + ")"
	}
	return strings.Join(parts, ", ")
}

// count writes a number with the right form of a word.
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// worst returns the highest level among the findings for a reference.
func (b *builder) worst(ref string) Level {
	worst := Plain
	for _, f := range b.byRef[ref] {
		if l := level(f.Severity); l > worst {
			worst = l
		}
	}
	return worst
}

// said adds what the rules said about an item to its lines of detail.
func (b *builder) said(lines []Line, refs ...string) []Line {
	for _, ref := range refs {
		for _, f := range b.byRef[ref] {
			lines = append(lines,
				Line{Heading, f.Severity.String() + ": " + f.Title},
				Line{Text, f.Reason},
				Line{Text, "What you can do: " + f.Advice})
		}
	}
	return lines
}

// fact adds a labelled line when there is something to say.
func fact(lines []Line, label, value string) []Line {
	if strings.TrimSpace(value) == "" {
		return lines
	}
	return append(lines, Line{Text, label + ": " + value})
}

// byLevel puts the rows that deserve attention first and otherwise keeps
// their order.
func byLevel(rows []Row) {
	rank := func(l Level) int {
		switch l {
		case First:
			return 0
		case Look:
			return 1
		case Info:
			return 2
		}
		return 3
	}
	sort.SliceStable(rows, func(i, j int) bool { return rank(rows[i].Level) < rank(rows[j].Level) })
}

// unseen returns what could not be read in an area.
func (b *builder) unseen(areas ...model.Area) []string {
	var notes []string
	for _, gap := range b.s.Gaps {
		for _, area := range areas {
			if gap.Area == area {
				notes = append(notes, gap.What)
			}
		}
	}
	return notes
}

// ago says how long before the look something happened, in days.
func ago(days int) string {
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "yesterday"
	}
	return fmt.Sprintf("%d days ago", days)
}
