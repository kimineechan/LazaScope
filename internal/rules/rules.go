// Package rules decides what on a PC is worth a second look, and says why.
//
// Every rule is a plain function over the facts in a model.Snapshot. It
// calls nothing, reads nothing from disk and has no window, so each rule
// can be tested with a made-up PC, and another program can use the same
// rules on its own facts.
//
// A finding is never a verdict. It says "worth a look" and gives the
// reason, because the same sign that marks an intruder also marks plenty of
// honest software.
package rules

import (
	"sort"
	"strconv"
	"strings"

	"lazascope/internal/model"
)

// Severity is how soon a finding deserves attention.
type Severity int

const (
	Low    Severity = iota // good to know, or worth tidying up
	Medium                 // worth a look
	High                   // look at this first
)

func (s Severity) String() string {
	switch s {
	case High:
		return "Look first"
	case Medium:
		return "Worth a look"
	}
	return "Good to know"
}

// Fact is one piece of the evidence for a finding.
type Fact struct{ Label, Value string }

// Finding is one thing a rule flagged.
type Finding struct {
	Rule     string // the rule that made it, such as "startup-unsigned"
	Severity Severity
	Area     model.Area
	Title    string // what was found, in a few words
	Subject  string // what it is about: an entry, a program, a setting
	Reason   string // why it matters
	Advice   string // what the user can do about it
	Facts    []Fact // the evidence
	Ref      string // which item of the snapshot it is about, so that a list can mark that item
}

// Rule is one written rule.
type Rule struct {
	ID       string
	Area     model.Area
	Severity Severity // the usual severity; a finding may be raised or lowered from it
	Title    string
	Why      string // why the rule exists, in one or two sentences
	Topic    string // what its findings are about, when that is always the same setting
	check    func(s *model.Snapshot, r *Rule) []Finding
	ref      string // what the finding being made is about
}

// at notes which item the next findings are about.
func (r *Rule) at(ref string) { r.ref = ref }

// find starts a finding of this rule.
func (r *Rule) find(subject, reason, advice string, facts ...Fact) Finding {
	var kept []Fact
	for _, fact := range facts {
		if fact.Value != "" {
			kept = append(kept, fact)
		}
	}
	ref := r.ref
	if ref == "" {
		ref = r.Topic
	}
	return Finding{Rule: r.ID, Severity: r.Severity, Area: r.Area, Title: r.Title, Subject: subject, Reason: reason, Advice: advice, Facts: kept, Ref: ref}
}

// The references findings carry. A list that shows the snapshot builds the
// same reference for each of its rows, and so finds the findings that
// belong to a row.

// StartupRef refers to a start-up entry by its place in the snapshot.
func StartupRef(index int) string { return "startup:" + strconv.Itoa(index) }

// ProcessRef refers to one running program by its number.
func ProcessRef(pid uint32) string { return "process:" + strconv.Itoa(int(pid)) }

// FileRef refers to every running copy of a program file.
func FileRef(path string) string { return "file:" + strings.ToLower(path) }

// ListenRef refers to the ports a program file waits on.
func ListenRef(path string) string { return "listen:" + strings.ToLower(path) }

// DiskRef refers to a drive.
func DiskRef(drive string) string { return "disk:" + strings.ToUpper(drive) }

// RemoteRef refers to a remote-control program by its name.
func RemoteRef(name string) string { return "remote:" + name }

// AdminRef refers to an account in the Administrators group.
func AdminRef(name string) string { return "admin:" + strings.ToLower(name) }

// All returns every rule, in the order of the six areas.
func All() []Rule {
	var all []Rule
	for _, group := range [][]Rule{protectionRules, historyRules, networkRules, startupRules, runningRules, connectionRules, accountRules, healthRules} {
		all = append(all, group...)
	}
	return all
}

// Check runs every rule over a snapshot and returns what they flagged, the
// most serious first.
func Check(s *model.Snapshot) []Finding {
	var findings []Finding
	for _, rule := range All() {
		rule := rule
		findings = append(findings, rule.check(s, &rule)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Area != b.Area {
			return a.Area < b.Area
		}
		return false
	})
	return findings
}

// Light is the colour of one of the six lights on the overview page.
type Light int

const (
	Grey  Light = iota // could not be read
	Green              // nothing worth a look
	Amber              // something worth a look
	Red                // something to look at first
)

func (l Light) String() string {
	switch l {
	case Green:
		return "Nothing stands out"
	case Amber:
		return "Worth a look"
	case Red:
		return "Look at this first"
	}
	return "Could not be read"
}

// Lights returns the colour of each area. Findings that are only good to
// know leave a light green. An area of which nothing at all could be read
// stays grey, so that an empty list is not taken for a clean one.
func Lights(s *model.Snapshot, findings []Finding) [model.Areas]Light {
	var lights [model.Areas]Light
	read := [model.Areas]bool{
		model.Protection:        s.Guard.Build != "" || len(s.Guard.Firewall) > 0,
		model.StartsWithWindows: len(s.Startup) > 0,
		model.RunningNow:        len(s.Processes) > 0,
		model.Connections:       len(s.Connections) > 0,
		model.Accounts:          s.Guard.Build != "" || s.Guard.AdminsVisible,
		model.Health:            s.Condition.Read || len(s.Condition.Drives) > 0,
	}
	for area := range lights {
		if read[area] {
			lights[area] = Green
		}
	}
	for _, f := range findings {
		switch {
		case f.Severity == High:
			lights[f.Area] = Red
		case f.Severity == Medium && lights[f.Area] != Red:
			lights[f.Area] = Amber
		}
	}
	return lights
}

// Count returns how many findings an area has at each severity.
func Count(findings []Finding, area model.Area) (high, medium, low int) {
	for _, f := range findings {
		if f.Area != area {
			continue
		}
		switch f.Severity {
		case High:
			high++
		case Medium:
			medium++
		default:
			low++
		}
	}
	return
}

// list joins a few values for a sentence and says how many more there are.
func list(values []string, most int) string {
	if len(values) > most {
		return strings.Join(values[:most], ", ") + " and " + plural(len(values)-most, "other", "others")
	}
	if len(values) < 2 {
		return strings.Join(values, "")
	}
	return strings.Join(values[:len(values)-1], ", ") + " and " + values[len(values)-1]
}

// plural writes a count with the right form of a word.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
