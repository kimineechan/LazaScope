package rules

import (
	"fmt"
	"lazascope/internal/i18n"
	"strings"
	"time"

	"lazascope/internal/model"
)

// What VirusTotal's engines said about the files on the PC, when the person
// using LazaScope set up a VirusTotal key of their own and had files looked
// up. VirusTotal is a website, owned by Google, that runs each file it is
// shown through about 70 antivirus engines. The judgement is theirs: these
// rules pass it on, and say how much weight it bears.

var virusTotalRules = []Rule{
	{
		ID: "startup-virustotal-flags", Area: model.StartsWithWindows, Severity: Medium,
		Title: i18n.T("Antivirus engines on VirusTotal flag something that starts by itself"),
		Why:   i18n.T("VirusTotal runs each file it is shown through about 70 antivirus engines. When some of them flag a program that starts with Windows, that is worth a look. One or two flags on a little-known or home-made program are often false alarms; many flags are a strong sign."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				works := e.Works()
				rep, ok := s.Reputation(works.Path)
				if !e.Enabled || !ok || !rep.Known || rep.Flags() == 0 {
					continue
				}
				r.at(StartupRef(i))
				f := r.find(e.Shown(), flagReason(s, rep), flagAdvice(rep, "03 Start-up")+" "+stop(e.Kind), append(about(e), flagFacts(s, rep)...)...)
				f.Severity = FlagSeverity(rep)
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "running-virustotal-flags", Area: model.RunningNow, Severity: Medium,
		Title: i18n.T("Antivirus engines on VirusTotal flag a running program"),
		Why:   i18n.T("VirusTotal runs each file it is shown through about 70 antivirus engines. When some of them flag a program that is running now, that is worth a look. A program that also starts by itself is flagged once, under what starts by itself."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			starts := map[string]bool{}
			for _, e := range s.Startup {
				if e.Enabled {
					starts[strings.ToLower(e.Works().Path)] = true
				}
			}
			for _, p := range once(s.Processes) {
				rep, ok := s.Reputation(p.File.Path)
				if !ok || !rep.Known || rep.Flags() == 0 || starts[strings.ToLower(p.File.Path)] {
					continue
				}
				r.at(FileRef(p.File.Path))
				f := r.find(p.Name, flagReason(s, rep), seeRunning+flagAdvice(rep, "04 Running"), append(aboutProcess(s, p), flagFacts(s, rep)...)...)
				f.Severity = FlagSeverity(rep)
				found = append(found, f)
			}
			return
		},
	},
}

// FlagSeverity weighs what the engines said: five or more that call a file
// harmful is a strong sign, two to four is worth a look, and a single one,
// or flags of suspicion alone, is often a false alarm.
func FlagSeverity(r model.Reputation) Severity {
	switch {
	case r.Malicious >= 5:
		return High
	case r.Malicious >= 2:
		return Medium
	}
	return Low
}

// VirusTotalSays sums up an answer in a sentence without its full stop,
// such as "7 of 71 antivirus engines flag it".
func VirusTotalSays(r model.Reputation) string {
	switch {
	case !r.Known:
		return "VirusTotal has never seen this file"
	case r.Engines() == 0:
		return "VirusTotal knows this file, but has no engines' verdicts on it yet"
	case r.Flags() == 0:
		return fmt.Sprintf("none of the %d antivirus engines flags it", r.Engines())
	}
	text := fmt.Sprintf("%d of %d antivirus engines flag it", r.Flags(), r.Engines())
	switch {
	case r.Malicious > 0 && r.Suspicious > 0:
		text += fmt.Sprintf(": %d call it harmful and %d suspicious", r.Malicious, r.Suspicious)
	case r.Suspicious > 0:
		text += ", as suspicious rather than harmful"
	}
	return text
}

func flagReason(s *model.Snapshot, r model.Reputation) string {
	reason := "VirusTotal, asked by this file's fingerprint, reports that " + VirusTotalSays(r) + "."
	if r.Label != "" {
		reason += " Its own label for the file is " + r.Label + "."
	}
	if !r.Analysed.IsZero() {
		reason += " The engines last looked at the file on " + r.Analysed.In(location(s)).Format("2 January 2006") + "."
	}
	return reason + " That is their judgement, gathered by VirusTotal, not LazaScope's."
}

func flagAdvice(r model.Reputation, page string) string {
	if FlagSeverity(r) == High {
		return "Do not open it. Select it under " + page + " and choose Look up file... to read on VirusTotal's page what each engine calls it, then run a full scan with your antivirus. Unless you installed it yourself and know why it is flagged, ask someone who knows Windows well to remove it."
	}
	return "One or two flags on a little-known or home-made program are often false alarms, and some engines flag remote-control and system tools as unwanted rather than harmful. Select it under " + page + " and choose Look up file... to read on VirusTotal's page what each engine calls it. If you know the program and installed it yourself, nothing needs doing."
}

// flagFacts is the evidence: the count, the label and the engines' names.
func flagFacts(s *model.Snapshot, r model.Reputation) []Fact {
	facts := []Fact{{"VirusTotal", strings.ToUpper(VirusTotalSays(r)[:1]) + VirusTotalSays(r)[1:] + ", asked on " + r.Asked.In(location(s)).Format("2 January 2006")}}
	if r.Label != "" {
		facts = append(facts, Fact{"VirusTotal's label", r.Label})
	}
	var names []string
	for i, n := range r.Names {
		if i == 6 {
			names = append(names, fmt.Sprintf("and %d more", len(r.Names)-i))
			break
		}
		names = append(names, n.Engine+": "+n.Name)
	}
	if len(names) > 0 {
		facts = append(facts, Fact{"What the engines call it", strings.Join(names, "; ")})
	}
	return facts
}

// location is the time zone the look was taken in.
func location(s *model.Snapshot) *time.Location {
	if s.Taken.IsZero() {
		return time.Local
	}
	return s.Taken.Location()
}
