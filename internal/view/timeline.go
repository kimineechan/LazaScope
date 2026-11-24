package view

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/winpath"
)

// timelineDays is how far back the timeline reaches.
const timelineDays = 90

// event is one moment on the timeline.
type event struct {
	when       time.Time
	what, item string
	source     string
	ref        string // a finding's reference, to colour the row by
	path       string
	lines      []Line
}

// timeline puts everything LazaScope can date in one list, newest first:
// programs started and opened, files changed and downloaded, what Defender
// did, and what Windows' logs say of the hardware.
func (b *builder) timeline() Page {
	s := b.s
	page := Page{
		Name: "Timeline", Title: "What happened when",
		Intro:   "Everything LazaScope can put a date to, newest first, over the last 90 days: programs started and opened, files changed and downloaded, what Defender did, and what Windows' logs say. Times are this PC's.",
		Columns: []Column{{"When", 168}, {"What", 300}, {"Source", 170}, {"About", 0}},
	}
	var events []event
	add := func(e event) {
		if e.when.IsZero() || s.Taken.Sub(e.when) > timelineDays*24*time.Hour || e.when.After(s.Taken.Add(time.Hour)) {
			return
		}
		events = append(events, e)
	}
	for _, r := range s.Ran {
		what := "Opened by this account"
		lines := []Line{{Text, "Windows' UserAssist record says this account opened it from the desktop, Explorer or Start."}}
		if r.Source == "BAM" {
			what = "Ran"
			lines = []Line{{Text, "Windows' Background Activity Moderator (BAM) records the last time each program ran for this account."}}
		}
		if r.Count > 0 {
			lines = append(lines, Line{Text, fmt.Sprintf("Times opened: %d.", r.Count)})
		}
		if r.Focus > 0 {
			lines = append(lines, Line{Text, "Time in front, all told: " + r.Focus.Round(time.Second).String() + "."})
		}
		add(event{when: r.Last, what: what, item: runName(r.Path), source: r.Source, path: r.Path, lines: append(lines, Line{Command, r.Path})})
	}
	for i, e := range s.Startup {
		works := e.Works()
		if !works.Exists || windowsEntry(e, s.Folders) {
			continue
		}
		add(event{when: works.Modified, what: "File of a start-up entry changed", item: e.Shown(), source: "File time", ref: rules.StartupRef(i), path: works.Path,
			lines: []Line{{Text, "The file this start-up entry runs was last changed then: usually when it was installed or updated."}, {Command, works.Path}}})
		if o := works.Origin; o != nil {
			add(event{when: works.Modified, what: "Downloaded file starts by itself", item: e.Shown(), source: "Download mark", ref: rules.StartupRef(i), path: works.Path,
				lines: append([]Line{{Text, "Windows marked this file as downloaded."}}, originLines(o)...)})
		}
	}
	// A program that runs as many copies, as browsers do, is one moment: the
	// first copy's start.
	first := map[string]model.Process{}
	copies := map[string]int{}
	var order []string
	for _, p := range s.Processes {
		if p.Self || p.File.Path == "" || partOfWindows(p.File, s.Folders) {
			continue
		}
		key := strings.ToLower(p.File.Path)
		if _, seen := first[key]; !seen {
			order = append(order, key)
		}
		if q, seen := first[key]; !seen || (!p.Started.IsZero() && p.Started.Before(q.Started)) {
			first[key] = p
		}
		copies[key]++
	}
	for _, key := range order {
		p, n := first[key], copies[key]
		item := p.Name
		text := fmt.Sprintf("Process %d started then, and is still running.", p.PID)
		if n > 1 {
			item = fmt.Sprintf("%s (%d copies)", p.Name, n)
			text = fmt.Sprintf("The first of %d copies of this program now running started then, as process %d.", n, p.PID)
		}
		add(event{when: p.Started, what: "Started", item: item, source: "Running now", ref: rules.FileRef(p.File.Path), path: p.File.Path,
			lines: []Line{{Text, text}, {Command, p.File.Path}}})
		if o := p.File.Origin; o != nil {
			add(event{when: p.File.Modified, what: "Downloaded file is running", item: p.Name, source: "Download mark", ref: rules.FileRef(p.File.Path), path: p.File.Path,
				lines: append([]Line{{Text, "Windows marked this file as downloaded. Its time is when it was saved."}}, originLines(o)...)})
		}
	}
	g, c := s.Guard, s.Condition
	for _, d := range g.Detections {
		add(event{when: d.When, what: "Defender found " + d.Threat, item: winpath.Base(d.Path), source: "Defender's log", ref: "detections", path: d.Path,
			lines: []Line{{Text, "Defender's action: " + orNone(d.Action) + "."}, {Command, d.Path}}})
	}
	for _, e := range g.LoggedExclusions {
		add(event{when: e.When, what: "Defender told to skip a place", item: e.Value, source: "Defender's log", ref: "exclusions", lines: []Line{{Text, e.Kind + ":"}, {Command, e.Value}}})
	}
	for _, when := range g.SwitchedOff {
		add(event{when: when, what: "Defender's real-time protection switched off", item: "Microsoft Defender", source: "Defender's log", ref: "realtime"})
	}
	if g.UpdateKnown {
		add(event{when: g.LastUpdate, what: "Windows update installed", item: "Windows Update", source: "Windows Update", ref: "updates"})
	}
	for _, f := range c.Hardware {
		add(event{when: f.When, what: "Hardware error", item: f.Part, source: "System log", ref: "hardware", lines: []Line{{Text, f.Words}}})
	}
	for _, crash := range c.Crashes {
		add(event{when: crash.When, what: "Blue screen", item: fmt.Sprintf("0x%X %s", crash.Code, crash.Name), source: "System log", ref: "crashes"})
	}
	for _, when := range c.PowerCuts {
		add(event{when: when, what: "Went off without shutting down", item: "Windows", source: "System log", ref: "stops"})
	}
	for _, f := range c.Disk {
		add(event{when: f.When, what: "Disk fault", item: orNone(f.Where), source: "System log", ref: "disk", lines: []Line{{Text, f.Words}}})
	}
	for _, w := range c.Wiped {
		add(event{when: w.When, what: "Log cleared", item: w.Log, source: "Event log", ref: "wiped", lines: []Line{{Text, "Cleared by " + orNone(w.By) + "."}}})
	}
	if !c.Started.IsZero() {
		add(event{when: c.Started, what: "Windows started", item: "Windows", source: "System"})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].when.After(events[j].when) })
	if len(events) > 1000 {
		events = events[:1000]
	}
	for _, e := range events {
		row := Row{Ref: "event:" + e.ref, Level: Plain, Path: e.path, When: e.when}
		if e.ref != "" {
			row.Level = b.worst(e.ref)
		}
		local := e.when.In(location(s))
		row.Cells = []string{local.Format("2006-01-02 15:04:05"), e.what, e.source, e.item}
		lines := []Line{{Heading, e.what}, {Text, local.Format("Monday 2 January 2006, 15:04:05") + " (" + e.when.UTC().Format("15:04:05") + " UTC)."}}
		lines = append(lines, e.lines...)
		if e.ref != "" {
			lines = b.said(lines, e.ref)
		}
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}
	return page
}

// location is the time zone the look was taken in.
func location(s *model.Snapshot) *time.Location {
	if s.Taken.IsZero() {
		return time.Local
	}
	return s.Taken.Location()
}

// runName is the short name of what a run record is about.
func runName(path string) string {
	if strings.Contains(path, `\`) {
		return winpath.Base(path)
	}
	return path // an app's name, such as Microsoft.WindowsCalculator_8wekyb3d8bbwe!App
}

// originLines say where a downloaded file came from.
func originLines(o *model.Origin) []Line {
	lines := []Line{{Text, "Downloaded from " + zoneName(o.Zone) + "."}}
	if o.Host != "" {
		lines = append(lines, Line{Link, "From: " + o.Host})
	}
	if o.Referrer != "" {
		lines = append(lines, Line{Link, "Linked from: " + o.Referrer})
	}
	return lines
}

func zoneName(zone int) string {
	switch zone {
	case 0:
		return "this PC"
	case 1:
		return "the local network"
	case 2:
		return "a trusted site"
	case 3:
		return "the internet"
	case 4:
		return "a restricted site"
	}
	return "an unknown zone"
}
