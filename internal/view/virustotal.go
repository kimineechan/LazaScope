package view

import (
	"fmt"
	"slices"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/virustotal"
)

// VirusTotalHeading heads what VirusTotal said in a file's details, so
// that the window can tell whether the details hold it already.
const VirusTotalHeading = "What VirusTotal's engines say"

// VirusTotalLines says what VirusTotal said about a file, for its details.
func VirusTotalLines(r model.Reputation, print string) []Line {
	says := rules.VirusTotalSays(r)
	lines := []Line{{Heading, VirusTotalHeading}, {Text, strings.ToUpper(says[:1]) + says[1:] + "."}}
	switch {
	case !r.Known:
		lines = append(lines, Line{Text, "That is normal for programs that are new, rare or made at home, and is not a bad sign in itself. LazaScope sends only the fingerprint, never the file, so VirusTotal has still not seen it."})
	case r.Engines() > 0:
		if r.Label != "" {
			lines = append(lines, Line{Text, "VirusTotal's own label for it: " + r.Label + "."})
		}
		if len(r.Names) > 0 {
			lines = append(lines, Line{Text, "What the engines that flag it call it:"})
			for _, n := range r.Names {
				lines = append(lines, Line{Command, n.Engine + ": " + n.Name})
			}
		}
		if !r.Analysed.IsZero() {
			lines = append(lines, Line{Text, "The engines last looked at it on " + r.Analysed.Local().Format("2 January 2006") + "."})
		}
		if r.Votes != 0 {
			lines = append(lines, Line{Text, fmt.Sprintf("The VirusTotal community's score for it is %+d. People who use VirusTotal vote on files; below zero means more of them called it harmful.", r.Votes)})
		}
	}
	lines = append(lines, Line{Aside, "VirusTotal was asked on " + r.Asked.Local().Format("2 January 2006") + ", by the file's fingerprint only. This is the judgement of the engines VirusTotal runs, not LazaScope's."})
	if page := virustotal.Page(print); page != "" {
		lines = append(lines, Line{Link, "VirusTotal's page about it: " + page})
	}
	return lines
}

// reputationLevel is how much attention a file deserves for what
// VirusTotal said about it, on the same scale as the findings.
func reputationLevel(r model.Reputation) Level {
	switch {
	case !r.Known || r.Engines() == 0:
		return Unknown
	case r.Flags() == 0:
		return Fine
	}
	return level(rules.FlagSeverity(r))
}

// withVirusTotal adds a column for what VirusTotal said to a list of files,
// at the place given, once any file has been looked up. The columns in
// narrower are made that much narrower to make room.
func (b *builder) withVirusTotal(page *Page, at int, narrower map[int]int) {
	if len(b.s.VirusTotal) == 0 {
		return
	}
	for i, by := range narrower {
		page.Columns[i].Width -= by
	}
	page.Columns = slices.Insert(page.Columns, at, Column{"VirusTotal", 96})
	for i := range page.Rows {
		cell := ""
		if r, ok := b.s.Reputation(page.Rows[i].Path); ok {
			cell = virustotal.Says(r)
		}
		page.Rows[i].Cells = slices.Insert(page.Rows[i].Cells, at, cell)
	}
}

// virusTotal lists the files worth asking VirusTotal about, with what it
// said about each so far.
func (b *builder) virusTotal() Page {
	s := b.s
	page := Page{
		Name: "VirusTotal", Title: "What VirusTotal's engines say about the programs on this PC",
		Intro:   "VirusTotal is a website, owned by Google, that runs each file it is shown through about 70 antivirus engines. With a free key of your own, LazaScope asks it about the programs that start by themselves or are running, by their fingerprints only. Microsoft's own signed files are left out.",
		Columns: []Column{{"VirusTotal", 112}, {"Program", 240}, {"Seen", 196}, {"Maker", 224}, {"File", 0}},
	}
	for _, c := range virustotal.Candidates(s, b.findings) {
		row := Row{Path: c.Path, Level: Plain}
		print := s.Fingerprint(c.Path)
		r, asked := s.VirusTotal[print]
		asked = asked && print != ""
		says := "Not asked yet"
		if asked {
			says, row.Level = virustotal.Says(r), reputationLevel(r)
		}
		var seen []string
		if c.Starts {
			seen = append(seen, "starts by itself")
		}
		if c.Runs {
			seen = append(seen, "running")
		}
		where := and(seen)
		where = strings.ToUpper(where[:1]) + where[1:]
		row.Cells = []string{says, c.Name, where, c.Maker, c.Path}
		lines := []Line{{Heading, c.Name}, {Text, "File:"}, {Command, c.Path}}
		if c.Flagged {
			lines = append(lines, Line{Text, "A rule flagged this file. It is under 08 Worth a look."})
		}
		if print != "" {
			lines = append(lines, Line{Text, "Fingerprint (SHA-256):"}, Line{Command, print})
		}
		if asked {
			lines = append(lines, VirusTotalLines(r, print)...)
		} else {
			lines = append(lines, Line{Text, "VirusTotal has not been asked about this file yet."})
		}
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}
	byLevel(page.Rows) // what the engines flag comes first
	return page
}
