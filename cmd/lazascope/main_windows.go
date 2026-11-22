//go:build windows

// LazaScope shows what a Windows PC is doing and what on it is worth a
// second look. It only reads: nothing on the PC is changed, and nothing
// leaves it.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lazascope"
	"lazascope/internal/model"
	"lazascope/internal/report"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
	"lazascope/internal/winui"
)

// The layout, in the units winui scales to the screen.
const (
	width, height = 1040, 764
	left, across  = 32, 976 // the margin, and the room between the margins
)

const reportFilter = "Web page, to read or send (*.html)\x00*.html\x00Plain text (*.txt)\x00*.txt\x00Data for other tools (*.json)\x00*.json\x00\x00"

// The pages, in the order of their section buttons.
const (
	pageOverview = iota
	pageProtection
	pageStartup
	pageRunning
	pageConnections
	pageAccounts
	pageWorth
)

// areaPage is the page that shows an area's list.
var areaPage = [model.Areas]int{
	model.Protection: pageProtection, model.StartsWithWindows: pageStartup, model.RunningNow: pageRunning,
	model.Connections: pageConnections, model.Accounts: pageAccounts,
}

// filter is one way of narrowing a list.
type filter struct {
	name string
	keep func(row view.Row) bool
}

func everything(view.Row) bool { return true }
func flagged(row view.Row) bool {
	return row.Level == view.Look || row.Level == view.First || row.Level == view.Info
}

// notWindows leaves out the parts of Windows itself, which are most of
// every list. A part of Windows that a rule flagged is kept: a filter must
// never hide a finding.
func notWindows(row view.Row) bool { return !row.Windows || flagged(row) }

// list is one page that shows a table with a box of detail under it.
type list struct {
	page    *view.Page
	filters []filter
	choice  *winui.Control // which filter is in use; nil for a page with none
	count   *winui.Control
	table   *winui.Control
	detail  *winui.Control
	shown   []view.Row // the rows in the table, after the filter
	picked  int        // the chosen row of shown, or -1
}

// tint is the colour of the first cell of a row.
func tint(row view.Row) winui.Colour {
	switch row.Level {
	case view.First:
		return winui.Red
	case view.Look:
		return winui.Amber
	case view.Fine:
		return winui.Green
	case view.Info, view.Unknown:
		return winui.Grey
	}
	if row.Off {
		return winui.Grey
	}
	return 0
}

// paragraphs turns lines of detail into what a Reader shows.
func paragraphs(lines []view.Line) []winui.Paragraph {
	out := make([]winui.Paragraph, len(lines))
	for i, line := range lines {
		out[i] = winui.Paragraph{Text: line.Text, Style: map[view.Style]winui.Style{view.Text: winui.Body, view.Heading: winui.Head, view.Aside: winui.Fine, view.Command: winui.Code}[line.Style]}
	}
	return out
}

// fill puts the page's rows in the table, as the filter in use allows.
func (l *list) fill() {
	keep := everything
	if l.choice != nil && l.choice.Chosen() >= 0 && l.choice.Chosen() < len(l.filters) {
		keep = l.filters[l.choice.Chosen()].keep
	}
	l.shown, l.picked = l.shown[:0], -1
	var cells [][]string
	var tints []winui.Colour
	// The running programs are set in from the left to show what started
	// what. With some of them left out that would mislead, so a narrowed
	// list is flat.
	flat := len(l.shown) == 0 && l.choice != nil && l.choice.Chosen() > 0
	for _, row := range l.page.Rows {
		if keep(row) {
			l.shown = append(l.shown, row)
			shown := row.Cells
			if flat && len(shown) > 1 && strings.HasPrefix(shown[1], " ") {
				shown = append([]string{}, shown...)
				shown[1] = strings.TrimLeft(shown[1], " ")
			}
			cells = append(cells, shown)
			tints = append(tints, tint(row))
		}
	}
	l.table.Fill(cells, tints)
	switch {
	case len(l.page.Rows) == 0:
		l.count.SetText("Nothing to show.")
	case len(l.shown) == len(l.page.Rows):
		l.count.SetText(fmt.Sprintf("%d shown.", len(l.shown)))
	default:
		l.count.SetText(fmt.Sprintf("%d of %d shown.", len(l.shown), len(l.page.Rows)))
	}
	// Until a row is chosen, the box says what the page is and what could
	// not be read for it.
	lines := []view.Line{{Style: view.Heading, Text: l.page.Title}, {Style: view.Text, Text: "Select a row to read what it is and why it is there."}}
	if l.page.Name == "Worth a look" && len(l.page.Rows) == 0 {
		lines[1].Text = "Nothing on this PC stood out to the rules. That is not a promise that nothing is wrong: LazaScope only knows the signs it was taught."
	}
	if len(l.page.Unseen) > 0 {
		lines = append(lines, view.Line{Style: view.Heading, Text: "What could not be read"})
		for _, note := range l.page.Unseen {
			lines = append(lines, view.Line{Style: view.Text, Text: note})
		}
	}
	l.detail.Read(paragraphs(lines)...)
}

// pick shows the detail of a row of the table.
func (l *list) pick(row int) {
	if row >= 0 && row < len(l.shown) {
		l.picked = row
		l.detail.Read(paragraphs(l.shown[row].Detail)...)
	}
}

func main() {
	// "LazaScope.exe --report file" takes a look and writes the report
	// without showing a window, for someone helping from a distance.
	// "--demo" shows a made-up PC in place of this one.
	demo, reportTo := false, ""
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--demo":
			demo = true
		case "--report":
			if i+1 < len(os.Args) {
				reportTo = os.Args[i+1]
				i++
			}
		}
	}
	if reportTo != "" {
		os.Exit(headless(reportTo, demo))
	}

	w, err := winui.New("LazaScope | a plain look at this PC", "LazaScopeNativeWindow", width, height)
	if err != nil {
		winui.Fatal("LazaScope", err)
		return
	}
	w.Grip(100)
	w.Frame()
	w.Title("LazaScope", left, 24, 430, 40)
	w.Quiet("What starts. What runs. What is worth a second look.", left+1, 66, 880, 22)
	w.Strip(left, 104, across, 44)
	var nav []*winui.Control
	x := left + 4
	for i, section := range []struct {
		label string
		width int
	}{{"01  Overview", 126}, {"02  Protection", 132}, {"03  Start-up", 120}, {"04  Running", 118}, {"05  Connections", 144}, {"06  Accounts", 126}, {"07  Worth a look", 184}} {
		nav = append(nav, w.Section(section.label, i, x, 108, section.width, 36))
		x += section.width + 3
	}
	w.Rule(left, 722, across)
	status := w.Quiet("Ready. All work stays on this computer.", left, 730, across, 24)

	var book *view.Book
	var jobs []*winui.Control // what cannot be used while a look is being taken
	busy := false

	// 01  Overview
	w.Page(pageOverview)
	w.Heading("This PC at a glance", left, 166, across, 30)
	summary := w.Label("LazaScope is looking at this PC. It reads, and changes nothing.", left, 200, across, 42)
	w.Panel(left, 250, across, 246)
	var lamps, verdicts, facts [model.Areas]*winui.Control
	for area := model.Protection; area < model.Areas; area++ {
		y := 258 + int(area)*46
		lamps[area] = w.Light(left+14, y+12, 22, 22)
		w.Strong(area.String(), left+52, y+3, 290, 22)
		verdicts[area] = w.Line("Looking...", left+350, y+3, 420, 22)
		facts[area] = w.Note("", left+52, y+24, 760, 20)
		page := areaPage[area]
		w.Button("Open", left+across-118, y+7, 104, 32, func() { w.ShowPage(page) })
	}
	about := w.Box("", left, 508, across, 100)
	again := w.Button("Look again", left, 628, 200, 38, nil)
	raise := w.Button("Look again as administrator", left+212, 628, 250, 38, nil)
	save := w.Button("Save report...", left+across-266, 628, 266, 38, nil)
	save.Lead(true)
	jobs = append(jobs, again, raise, save)

	// The six lists.
	lists := map[int]*list{}
	addList := func(page int, files bool, filters []filter) {
		w.Page(page)
		l := &list{filters: filters, picked: -1}
		lists[page] = l
		heading := w.Heading("", left, 166, across, 30)
		intro := w.Label("", left, 200, across, 42)
		x := left
		if len(filters) > 0 {
			names := make([]string, len(filters))
			for i, f := range filters {
				names[i] = f.name
			}
			l.choice = w.Choice(names, left, 250, 330, 34, func() { l.fill() })
			x += 342
		}
		l.count = w.Caption("", x, 250, 300, 34)
		if files {
			w.Button("Show in folder", left+across-272, 250, 130, 34, func() {
				if l.picked < 0 || l.picked >= len(l.shown) {
					w.Info("Show in folder", "Select a row first.")
				} else if path := l.shown[l.picked].Path; path == "" {
					w.Info("Show in folder", "This row is not about a file on disk, so there is no folder to show.")
				} else {
					w.Reveal(path)
				}
			})
		}
		w.Button("Copy details", left+across-136, 250, 136, 34, func() {
			if w.Copy(l.detail.Words()) {
				status.SetText("Copied the details shown below the list.")
			}
		})
		// The columns come with the first look; until then the table has one.
		l.table = w.Table(left, 292, across, 244, []winui.Column{{Title: ""}}, func(row int) { l.pick(row) })
		l.detail = w.Reader(left, 544, across, 168)
		l.page = &view.Page{}
		// The heading and the introduction are set from the page itself.
		pageTexts[page] = [2]*winui.Control{heading, intro}
	}
	addList(pageProtection, false, nil)
	addList(pageStartup, true, []filter{{"Not part of Windows", notWindows}, {"Everything", everything}, {"Only what is worth a look", flagged}, {"Only what is switched on", func(row view.Row) bool { return !row.Off }}})
	addList(pageRunning, true, []filter{{"Everything, as a family tree", everything}, {"Not part of Windows", notWindows}, {"Only what is worth a look", flagged}})
	addList(pageConnections, true, []filter{
		{"Everything", everything},
		{"Connections to the internet", func(row view.Row) bool { return row.Group == "internet" }},
		{"Ports open to the network", func(row view.Row) bool { return row.Group == "waits" }},
		{"Not part of Windows", notWindows},
		{"Only what is worth a look", flagged},
	})
	addList(pageAccounts, false, nil)
	addList(pageWorth, true, nil)

	// show puts a finished look on every page.
	show := func(b *view.Book) {
		book = b
		summary.SetText(b.Summary)
		for area, glance := range b.Glances {
			tone, colour := winui.Off, winui.Grey
			switch glance.Light {
			case rules.Green:
				tone, colour = winui.Good, winui.Green
			case rules.Amber:
				tone, colour = winui.Warn, winui.Amber
			case rules.Red:
				tone, colour = winui.Bad, winui.Red
			}
			lamps[area].Show(tone)
			verdicts[area].SetText(glance.Verdict)
			verdicts[area].Tint(colour)
			facts[area].SetText(glance.Facts)
		}
		note := "LazaScope read this PC and changed nothing. It is not an antivirus: it shows what is there and what is unusual, and leaves the judging to you. Worth a look does not mean harmful."
		if unseen := len(b.Worth.Unseen); unseen > 0 && !b.Snapshot.Elevated {
			note += fmt.Sprintf("\r\nWithout administrator rights, %d things could not be read. They are listed under 07 Worth a look.", unseen)
		}
		about.SetText(note)
		raise.Enable(!b.Snapshot.Elevated && !demo)
		for index, page := range map[int]*view.Page{pageProtection: &b.Protection, pageStartup: &b.Startup, pageRunning: &b.Running, pageConnections: &b.Connections, pageAccounts: &b.Accounts, pageWorth: &b.Worth} {
			l := lists[index]
			l.page = page
			pageTexts[index][0].SetText(page.Title)
			pageTexts[index][1].SetText(page.Intro)
			columns := make([]winui.Column, len(page.Columns))
			for i, column := range page.Columns {
				columns[i] = winui.Column{Title: column.Title, Width: column.Width}
			}
			l.table.SetColumns(columns)
			l.fill()
		}
		nav[pageWorth].SetText(fmt.Sprintf("07  Worth a look (%d)", len(b.Findings)))
	}

	// look takes a look at the PC off the window's thread.
	look := func() {
		if busy {
			return
		}
		busy = true
		for _, c := range jobs {
			c.Enable(false)
		}
		status.SetText("Looking at this PC...")
		go func() {
			var s *model.Snapshot
			if demo {
				s = sample.PC()
			} else {
				s = scan.Run(scan.Everything, func(stage string) { w.Post(func() { status.SetText(stage) }) })
			}
			b := view.Build(s, rules.Check(s))
			w.Post(func() {
				busy = false
				for _, c := range jobs {
					c.Enable(true)
				}
				show(b)
				text := fmt.Sprintf("Looked at this PC in %.1f seconds. Nothing was changed. All work stays on this computer.", s.Took.Seconds())
				if demo {
					text = "This is a made-up PC, to show what findings look like. Start LazaScope without --demo to look at this one."
				}
				status.SetText(text)
			})
		}()
	}
	again.Do(look)
	raise.Do(func() {
		self, err := os.Executable()
		if err != nil {
			w.Alert("Look again as administrator", "LazaScope could not find its own file to start again.")
			return
		}
		// Windows asks before giving the rights. On a no, this window stays.
		if w.Elevated(self, "") {
			w.Close()
		}
	})
	save.Do(func() {
		if book == nil || busy {
			return
		}
		b := book
		name := fmt.Sprintf("LazaScope report %s %s.html", b.Snapshot.Computer, b.Snapshot.Taken.Format("2006-01-02"))
		path, err := w.FileDialog("Save the report", reportFilter, "html", name, true)
		if err != nil {
			w.Alert("Save the report", err.Error())
			return
		}
		if path == "" {
			return
		}
		if err := os.WriteFile(path, render(b, path), 0600); err != nil {
			w.Alert("Save the report", "The report could not be saved: "+sentence(err))
			return
		}
		status.SetText("Saved " + path)
		w.Info("Report saved", "The report names this PC, your account, the programs you run and the addresses they talk to. Read it before you send it to anyone.")
	})

	w.ShowPage(pageOverview)
	w.Post(look)
	w.Run()
}

// pageTexts holds the heading and the introduction of each list page.
var pageTexts = map[int][2]*winui.Control{}

// render writes the report in the form the file's name asks for.
func render(b *view.Book, path string) []byte {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return report.JSON(b, lazascope.Version())
	case ".txt":
		return []byte(report.Text(b, lazascope.Version()))
	}
	return report.HTML(b, lazascope.Version())
}

// headless takes a look and writes the report with no window.
func headless(path string, demo bool) int {
	var s *model.Snapshot
	if demo {
		s = sample.PC()
	} else {
		s = scan.Run(scan.Everything, nil)
	}
	b := view.Build(s, rules.Check(s))
	if err := os.WriteFile(path, render(b, path), 0600); err != nil {
		winui.Fatal("LazaScope", fmt.Errorf("the report could not be saved: %s", sentence(err)))
		return 1
	}
	return 0
}

// sentence turns an error into a message that starts with a capital and ends with a full stop.
func sentence(e error) string {
	text := e.Error()
	if text == "" {
		return "Unknown error."
	}
	text = strings.ToUpper(text[:1]) + text[1:]
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	return text
}
