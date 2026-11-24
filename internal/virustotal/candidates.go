package virustotal

import (
	"sort"
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sigcheck"
)

// Candidate is a file worth asking VirusTotal about.
type Candidate struct {
	Path     string
	Name     string // what to call it: the start-up entry's name or the program's
	Size     int64
	Modified time.Time
	Maker    string
	Starts   bool // it starts by itself
	Runs     bool // it is running now
	Flagged  bool // a rule flagged it
	Signed   sigcheck.Status
}

// Candidates returns the files worth asking VirusTotal about: the programs
// that start by themselves or are running, and the files a rule flagged,
// the flagged ones first, then those whose signature is broken or missing.
//
// Files that carry a working signature from Microsoft are left out, even
// when a rule flagged them, as a rule does flag PowerShell when it runs a
// scrambled command: the signature already says who made them, and a free
// key's lookups are few. So is LazaScope itself, and anything switched off.
func Candidates(s *model.Snapshot, findings []rules.Finding) []Candidate {
	flagged := map[string]bool{}
	for _, f := range findings {
		for _, fact := range f.Facts {
			if fact.Label == "File" {
				flagged[strings.ToLower(fact.Value)] = true
			}
		}
	}
	byPath := map[string]*Candidate{}
	var order []string
	add := func(f model.File, name string, starts, runs bool) {
		key := strings.ToLower(f.Path)
		if f.Path == "" || !f.Exists || f.Signature.FromMicrosoft() || (!f.Program && !flagged[key]) {
			return
		}
		c := byPath[key]
		if c == nil {
			c = &Candidate{Path: f.Path, Name: name, Size: f.Size, Modified: f.Modified, Maker: f.Maker(), Flagged: flagged[key], Signed: f.Signature.Status}
			byPath[key] = c
			order = append(order, key)
		}
		c.Starts = c.Starts || starts
		c.Runs = c.Runs || runs
	}
	self := map[string]bool{}
	for _, p := range s.Processes {
		if p.Self {
			self[strings.ToLower(p.File.Path)] = true
		}
	}
	for _, e := range s.Startup {
		if !e.Enabled || e.Extension != nil {
			continue
		}
		works := e.Works()
		if !self[strings.ToLower(works.Path)] {
			add(works, e.Shown(), true, false)
		}
		if e.Program.Path != works.Path && !self[strings.ToLower(e.Program.Path)] {
			add(e.Program, e.Shown(), true, false)
		}
	}
	for _, p := range s.Processes {
		if !p.Self && !self[strings.ToLower(p.File.Path)] {
			add(p.File, p.Name, false, true)
		}
	}
	rank := func(c *Candidate) int {
		switch {
		case c.Flagged:
			return 0
		case c.Signed == sigcheck.Invalid:
			return 1
		case c.Signed == sigcheck.Unsigned:
			return 2
		}
		return 3
	}
	out := make([]Candidate, 0, len(order))
	for _, key := range order {
		out = append(out, *byPath[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := rank(&out[i]), rank(&out[j]); a != b {
			return a < b
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}
