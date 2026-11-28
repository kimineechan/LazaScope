//go:build windows

// LazaScope shows what a Windows PC is doing and what on it is worth a
// second look. It only reads: nothing on the PC is changed, and nothing
// leaves it.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"lazascope"
	"lazascope/internal/compare"
	"lazascope/internal/files"
	"lazascope/internal/i18n"
	"lazascope/internal/model"
	"lazascope/internal/query"
	"lazascope/internal/report"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
	"lazascope/internal/virustotal"
	"lazascope/internal/winui"
)

// The layout, in the units winui scales to the screen.
const (
	width, height = 1160, 764
	left, across  = 32, 1096 // the margin, and the room between the margins
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
	pageHealth
	pageWorth
	pageVirusTotal // reached from the buttons at the top right, not from sections of their own
	pageWallets
	pageTimeline // reached from the Overview
	pageDefences
	pageDevices
	pageLive
)

// areaPage is the page that shows an area's list.
var areaPage = [model.Areas]int{
	model.Protection: pageProtection, model.StartsWithWindows: pageStartup, model.RunningNow: pageRunning,
	model.Connections: pageConnections, model.Accounts: pageAccounts, model.Health: pageHealth,
}

// filter is one way of narrowing a list.
type filter struct {
	name string
	keep func(row view.Row) bool
	none string // what to say when the list has rows and none of them is kept
}

// kept says how many rows are on show, and owns up to the one case where
// the view shows more than its name says: a part of Windows that a rule
// flagged stays in the list of what is not part of Windows.
func kept(shown []view.Row, all int, name string) string {
	text := fmt.Sprintf("%d of %d shown.", len(shown), all)
	if name != notWindowsName {
		return text
	}
	parts := 0
	for _, row := range shown {
		if row.Windows {
			parts++
		}
	}
	switch parts {
	case 0:
		return text
	case 1:
		return text + " 1 flagged part of Windows."
	}
	return text + fmt.Sprintf(" %d flagged parts of Windows.", parts)
}

const (
	notWindowsName = "Not part of Windows"
	whatIsNew      = "What is new"
)

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
	waiting bool       // the first look has not come back yet

	// prints holds the fingerprints worked out so far, by path in small
	// letters. Every list shares the one map.
	prints map[string]string

	// memory holds what VirusTotal said, when a key was set up. Every list
	// shares the one memory.
	memory *virustotal.Memory
}

// lookupAddress returns the page on VirusTotal for a file's fingerprint.
// Anything that is not a SHA-256 fingerprint gives no address, so that
// nothing but a fingerprint can ever be put into the address.
func lookupAddress(print string) (string, bool) {
	if len(print) != 64 {
		return "", false
	}
	for _, r := range print {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return "", false
		}
	}
	return "https://www.virustotal.com/gui/file/" + print, true
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
		out[i] = winui.Paragraph{Text: line.Text, Style: map[view.Style]winui.Style{view.Text: winui.Body, view.Heading: winui.Head, view.Aside: winui.Fine, view.Command: winui.Code, view.Excerpt: winui.Code, view.Link: winui.Code}[line.Style]}
	}
	return out
}

// fill puts the page's rows in the table, as the filter in use allows.
func (l *list) fill() {
	keep, none, name := everything, "", ""
	if l.choice != nil && l.choice.Chosen() >= 0 && l.choice.Chosen() < len(l.filters) {
		chosen := l.filters[l.choice.Chosen()]
		keep, none, name = chosen.keep, chosen.none, chosen.name
	}
	l.shown, l.picked = l.shown[:0], -1
	var cells [][]string
	var tints []winui.Colour
	// The running programs are set in from the left to show what started
	// what. With some of them left out that would mislead, so a narrowed
	// list is flat.
	flat := l.choice != nil && l.choice.Chosen() > 0
	for _, row := range l.page.Rows {
		if keep(row) && search.Match(query.Record{Fields: row.Fields, Text: row.Text}) {
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
	if l.waiting {
		// Nothing has been read yet. An empty list now must not look like a
		// clean one.
		l.count.SetText("Looking...")
		l.detail.Read(winui.Paragraph{Text: l.page.Title, Style: winui.Head}, winui.Paragraph{Text: "LazaScope is looking at this PC. That takes a few seconds, and this list fills in when it is done."})
		return
	}
	switch {
	case len(l.page.Rows) == 0:
		l.count.SetText("Nothing to show.")
	case !search.Empty():
		l.count.SetText(fmt.Sprintf("%d of %d match the search.", len(l.shown), len(l.page.Rows)))
	case len(l.shown) == len(l.page.Rows):
		l.count.SetText(fmt.Sprintf("%d shown.", len(l.shown)))
	default:
		l.count.SetText(kept(l.shown, len(l.page.Rows), name))
	}
	// Until a row is chosen, the box says what the page is and what could
	// not be read for it.
	lines := []view.Line{{Style: view.Heading, Text: l.page.Title}, {Style: view.Text, Text: "Select a row to read what it is and why it is there."}}
	switch {
	case l.page.Name == "Worth a look" && len(l.page.Rows) == 0:
		lines[1].Text = "Nothing on this PC stood out to the rules. That is not a promise that nothing is wrong: LazaScope only knows the signs it was taught."
	case len(l.page.Rows) == 0 && len(l.page.Unseen) > 0:
		// An empty list is not a clean one when the reading failed.
		lines[1].Text = "This list is empty because it could not be read, not because there is nothing there."
	case len(l.page.Rows) == 0:
		lines[1].Text = "Windows reported nothing for this list."
	case len(l.shown) == 0 && !search.Empty():
		lines[1].Text = "Nothing in this list matches the search. Clear the search box at the top to see the whole list."
	case len(l.shown) == 0:
		if none == "" {
			none = "Nothing in this list matches the view chosen above."
		}
		if name == whatIsNew && l.page.Compared {
			// Something was compared, and it showed nothing new here.
			none = "Nothing in this list is new, or came and went, in what was compared."
		}
		lines[1].Text = none + " Choose another view above to see the rest of the list."
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
		lines := l.withPrint(l.shown[row])
		if analystMode && len(l.shown[row].Raw) > 0 {
			lines = append(append(append([]view.Line{}, lines...), view.Line{Style: view.Heading, Text: view.AnalystHeading}), l.shown[row].Raw...)
		}
		l.detail.Read(paragraphs(lines)...)
	}
}

// The search typed at the top, and whether analyst mode is on. Every list
// follows them.
var (
	search      query.Query
	analystMode bool
)

// withPrint returns a row's lines of detail, with the fingerprint of its
// file and what VirusTotal said about it added when they came after the look.
func (l *list) withPrint(row view.Row) []view.Line {
	lines := row.Detail
	print := l.prints[strings.ToLower(row.Path)]
	if row.Path == "" || print == "" {
		return lines
	}
	has := func(text string) bool {
		for _, line := range lines {
			if line.Text == text {
				return true
			}
		}
		return false
	}
	if !has(print) { // the look had not worked it out
		lines = append(append([]view.Line{}, lines...),
			view.Line{Style: view.Heading, Text: "Fingerprint of the file (SHA-256)"}, view.Line{Style: view.Command, Text: print},
			view.Line{Style: view.Aside, Text: "A fingerprint is a long number worked out from every byte of a file. Two files with the same fingerprint are the same file, so it can be looked up without sending the file anywhere."})
	}
	if l.memory != nil && !has(view.VirusTotalHeading) {
		if r, ok := l.memory.Answer(print); ok {
			lines = append(append([]view.Line{}, lines...), view.VirusTotalLines(r, print)...)
		}
	}
	return lines
}

func main() {
	i18n.Init(os.Args)

	// "LazaScope.exe --report file" takes a look and writes the report
	// without showing a window, for someone helping from a distance.
	// "--demo" shows a made-up PC in place of this one.
	demo, reportTo := false, ""
	for i := 1; i < len(os.Args); i++ {
		// A copy started with administrator rights is handed the place the
		// first one was told to open at. Windows does not pass settings of
		// this kind on by itself.
		if place, ok := strings.CutPrefix(os.Args[i], "--place="); ok {
			os.Setenv("LAZASCOPE_PLACE", place)
			continue
		}
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
	}{{"01  " + i18n.T("Overview"), 126}, {"02  " + i18n.T("Protection"), 132}, {"03  " + i18n.T("Start-up"), 120}, {"04  " + i18n.T("Running"), 118}, {"05  " + i18n.T("Connections"), 144}, {"06  " + i18n.T("Accounts"), 126}, {"07  " + i18n.T("Health"), 110}, {"08  " + i18n.T("Worth a look"), 184}} {
		nav = append(nav, w.Section(section.label, i, x, 108, section.width, 36))
		x += section.width + 3
	}
	// The search box and analyst mode work on every list, and VirusTotal has
	// a page of its own; all three can be reached from every page.
	searchBox := w.Input("", left+345, 32, 285, 36, nil)
	searchBox.Hint("Search the lists, or type ? for help")
	analyst := w.Switch("Analyst mode", left+642, 32, 160, 36, nil)
	w.Button(i18n.T("Wallets..."), left+814, 32, 120, 36, func() { w.ShowPage(pageWallets) })
	w.Button(i18n.T("VirusTotal..."), left+across-150, 32, 150, 36, func() { w.ShowPage(pageVirusTotal) })
	w.Rule(left, 722, across)
	status := w.Quiet("Ready. All work stays on this computer.", left, 730, across, 24)

	var book *view.Book
	var jobs []*winui.Control // what cannot be used while a look is being taken
	busy := false

	// 01  Overview
	w.Page(pageOverview)
	w.Heading(i18n.T("This PC at a glance"), left, 166, across, 30)
	summary := w.Label("LazaScope is looking at this PC. It reads, and changes nothing.", left, 200, across, 42)
	w.Panel(left, 250, across, 266)
	var lamps, verdicts, facts [model.Areas]*winui.Control
	for area := model.Protection; area < model.Areas; area++ {
		y := 256 + int(area)*43
		lamps[area] = w.Light(left+14, y+10, 22, 22)
		w.Strong(area.String(), left+52, y+1, 290, 22)
		verdicts[area] = w.Line("Looking...", left+350, y+1, 520, 22)
		facts[area] = w.Note("", left+52, y+22, 860, 20)
		page := areaPage[area]
		w.Button(i18n.T("Open"), left+across-118, y+5, 104, 32, func() { w.ShowPage(page) })
	}
	about := w.Box("LazaScope is taking its first look: what starts by itself, what is running, what is talking to the network, whether the protections are on and how the PC is holding up. It only reads. Nothing on this PC is changed and nothing leaves it.", left, 526, across, 92)
	again := w.Button(i18n.T("Look again"), left, 628, 150, 38, nil)
	raise := w.Button(i18n.T("Look again as administrator"), left+162, 628, 264, 38, nil)
	against := w.Button(i18n.T("Compare with a report..."), left+438, 628, 226, 38, nil)
	watch := w.Button(i18n.T("Watch for a minute"), left+676, 628, 196, 38, nil)
	save := w.Button(i18n.T("Save report..."), left+across-212, 628, 212, 38, nil)
	save.Lead(true)
	jobs = append(jobs, again, raise, against, save)
	// More ways to look, each with a page of its own.
	w.Button(i18n.T("Timeline..."), left, 676, 150, 36, func() { w.ShowPage(pageTimeline) })
	w.Button(i18n.T("Protections to switch on..."), left+162, 676, 262, 36, func() { w.ShowPage(pageDefences) })
	w.Button(i18n.T("Camera and microphone..."), left+436, 676, 240, 36, func() { w.ShowPage(pageDevices) })
	w.Button(i18n.T("Watch programs start..."), left+688, 676, 230, 36, func() { w.ShowPage(pageLive) })

	// lookUp works out the fingerprint of the file a row is about and, on
	// a yes, opens VirusTotal's page for that fingerprint in the user's own
	// browser. This is the one thing in LazaScope that reaches the internet,
	// and it is the browser that does it, with the fingerprint and nothing else.
	prints := map[string]string{}
	working := false
	var vt *vtPanel // the VirusTotal page, made further down
	lookUp := func(l *list) {
		const title = "Look up file"
		switch {
		case l.picked < 0 || l.picked >= len(l.shown):
			w.Info(title, "Select a row first.")
			return
		case l.shown[l.picked].Path == "":
			w.Info(title, "This row is not about a file on disk, so there is nothing to look up.")
			return
		case demo:
			w.Info(title, "This is the made-up PC, so the file is not there to be read. On your own PC this button works out the file's fingerprint and offers to open VirusTotal's page for it in your browser.")
			return
		case working:
			return
		}
		path := l.shown[l.picked].Path
		ask := func(print string) {
			address, ok := lookupAddress(print)
			if !ok {
				return
			}
			if !w.Ask(title, "Look this file up on VirusTotal?\r\n\r\n"+path+"\r\n\r\nVirusTotal is a website, owned by Google, that shows what about 70 antivirus products say about a file. Your web browser will open its page for this file's fingerprint:\r\n\r\n"+print+
				"\r\n\r\nOnly the fingerprint is sent, and it is your browser that sends it. The file itself stays on this PC. If VirusTotal has never seen the file, it says so. That is common for new and home-made programs, and is not a bad sign in itself.\r\n\r\nTo see VirusTotal's answer here in LazaScope instead, set up a free key with the VirusTotal... button at the top right.\r\n\r\nOpen the page now?") {
				status.SetText("Nothing was sent. The fingerprint is shown with the file's details, and Copy details copies it.")
				return
			}
			if w.Browse(address) {
				status.SetText("Opened VirusTotal's page for the file in your browser. Only the file's fingerprint was sent.")
			} else {
				w.Alert(title, "Windows could not open your browser. You can type this address into it yourself:\r\n\r\n"+address)
			}
		}
		// With a key of the person's own, VirusTotal's answer is fetched and
		// shown here; without one, its page can be opened in the browser.
		use := func(print string) {
			if vt != nil && vt.client != nil {
				vt.lookUp(l, path, print)
			} else {
				ask(print)
			}
		}
		if print := prints[strings.ToLower(path)]; print != "" {
			use(print)
			return
		}
		working = true
		status.SetText("Working out the fingerprint of " + path + "...")
		go func() {
			print, err := files.Fingerprint(path)
			w.Post(func() {
				working = false
				if err != nil {
					status.SetText("The fingerprint could not be worked out. Nothing was sent.")
					w.Alert(title, "The file could not be read, so its fingerprint could not be worked out: "+sentence(err))
					return
				}
				prints[strings.ToLower(path)] = print
				status.SetText("Worked out the fingerprint of " + path + ".")
				if l.picked >= 0 && l.picked < len(l.shown) && l.shown[l.picked].Path == path {
					l.pick(l.picked)
				}
				use(print)
			})
		}()
	}

	// The seven lists.
	lists := map[int]*list{}
	addList := func(page int, files bool, filters []filter) {
		w.Page(page)
		l := &list{filters: filters, picked: -1, prints: prints}
		lists[page] = l
		heading := w.Heading("", left, 166, across, 30)
		intro := w.Label("", left, 200, across, 42)
		x := left
		if len(filters) > 0 {
			names := make([]string, len(filters))
			for i, f := range filters {
				names[i] = f.name
			}
			l.choice = w.Choice(names, left, 250, 270, 34, func() { l.fill() })
			x += 282
		}
		l.count = w.Caption("", x, 250, 384, 34)
		if files {
			w.Button(i18n.T("Look up file..."), left+across-422, 250, 142, 34, func() { lookUp(l) })
			w.Button(i18n.T("Show in folder"), left+across-272, 250, 130, 34, func() {
				if l.picked < 0 || l.picked >= len(l.shown) {
					w.Info("Show in folder", "Select a row first.")
				} else if path := l.shown[l.picked].Path; path == "" {
					w.Info("Show in folder", "This row is not about a file on disk, so there is no folder to show.")
				} else {
					w.Reveal(path)
				}
			})
		}
		w.Button(i18n.T("Copy details"), left+across-136, 250, 136, 34, func() {
			if w.Copy(l.detail.Words()) {
				status.SetText("Copied the details shown below the list.")
			} else {
				status.SetText("The details could not be copied, because another program is using the clipboard. Try again in a moment.")
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
	const (
		allWindows = "Everything in this list is a part of Windows."
		noneWorth  = "Nothing in this list was flagged by the rules."
		nothingNew = "Nothing in this list is marked as new. A look on its own has nothing to compare with: on the Overview, use Watch for a minute or Compare with a report first."
	)
	isNew := func(row view.Row) bool { return row.Fresh }
	addList(pageStartup, true, []filter{
		{notWindowsName, notWindows, allWindows},
		{"Everything", everything, ""},
		{"Only what is worth a look", flagged, noneWorth},
		{"Only what is switched on", func(row view.Row) bool { return !row.Off }, "Everything in this list is switched off."},
		{"Browser extensions", func(row view.Row) bool { return row.Group == "extension" }, "No extension was found in the browsers LazaScope knows: Chrome, Edge, Firefox, Brave, Vivaldi and Opera."},
		{whatIsNew, isNew, nothingNew},
	})
	addList(pageRunning, true, []filter{
		{"Everything, as a family tree", everything, ""},
		{notWindowsName, notWindows, allWindows},
		{"Only what is worth a look", flagged, noneWorth},
		{whatIsNew, isNew, nothingNew},
	})
	addList(pageConnections, true, []filter{
		{"Everything", everything, ""},
		{"Connections to the internet", func(row view.Row) bool { return row.Group == "internet" }, "No program is connected to the internet at the moment."},
		{"Ports open to the network", func(row view.Row) bool { return row.Group == "waits" }, "No program is waiting for connections from the network."},
		{notWindowsName, notWindows, allWindows},
		{"Only what is worth a look", flagged, noneWorth},
		{whatIsNew, isNew, nothingNew},
	})
	within := func(hours int) func(view.Row) bool {
		return func(row view.Row) bool {
			return book != nil && !row.When.IsZero() && book.Snapshot.Taken.Sub(row.When) <= time.Duration(hours)*time.Hour
		}
	}
	addList(pageTimeline, true, []filter{
		{"Everything, newest first", everything, ""},
		{"The last 24 hours", within(24), "Nothing LazaScope can date happened in the last 24 hours."},
		{"The last 7 days", within(7 * 24), "Nothing LazaScope can date happened in the last 7 days."},
		{"The last 30 days", within(30 * 24), "Nothing LazaScope can date happened in the last 30 days."},
		{"Only what is worth a look", flagged, noneWorth},
	})
	addList(pageDefences, false, nil)
	addList(pageDevices, true, nil)
	addList(pageAccounts, false, nil)
	addList(pageHealth, false, nil)
	addList(pageWorth, true, nil)
	// The ATT&CK techniques the findings may be traces of, as a layer for
	// MITRE's ATT&CK Navigator.
	layerButton := w.Button(i18n.T("Save ATT&CK layer..."), left+across-634, 250, 200, 34, func() {
		const title = "Save for the ATT&CK Navigator"
		if book == nil || busy {
			return
		}
		name := fmt.Sprintf("LazaScope ATT&CK layer %s %s.json", book.Snapshot.Computer, book.Snapshot.Taken.Format("2006-01-02"))
		path, err := w.FileDialog(title, "Layer for the ATT&CK Navigator (*.json)\x00*.json\x00\x00", "json", name, true)
		if err != nil {
			w.Alert(title, err.Error())
			return
		}
		if path == "" {
			return
		}
		content, count := report.NavigatorLayer(book, lazascope.Version())
		if err := os.WriteFile(path, content, 0600); err != nil {
			w.Alert(title, "The layer could not be saved: "+sentence(err))
			return
		}
		status.SetText("Saved " + path)
		colours := fmt.Sprintf("It colours in the %d ATT&CK techniques that the findings may be traces of.", count)
		switch count {
		case 0:
			colours = "None of the findings is a trace of an ATT&CK technique, so it colours nothing in."
		case 1:
			colours = "It colours in the one ATT&CK technique that a finding may be a trace of."
		}
		w.Info(title, "Saved a layer for MITRE's ATT&CK Navigator, the free web page that shows the whole ATT&CK catalogue as a grid. "+colours+
			"\r\n\r\nTo see it, open the Navigator at mitre-attack.github.io/attack-navigator in your web browser, choose Open Existing Layer, then Upload from local, and pick this file. The Navigator reads the file inside your browser.\r\n\r\nThe layer names this PC and what was found on it. Read it before you send it to anyone.")
	})
	jobs = append(jobs, layerButton)

	// The VirusTotal page.
	vt = newVirusTotal(w, status, demo, prints)
	vt.book = func() *view.Book { return book }
	vt.busy = func() bool { return busy }
	lists[pageVirusTotal] = vt.list

	// The Wallets page.
	wp := newWallets(w, status, demo, prints)
	wp.book = func() *view.Book { return book }
	wp.busy = func() bool { return busy }
	lists[pageWallets] = wp.list

	// The live watch, which keeps its own list.
	live := newLive(w, status, demo)
	for _, l := range lists {
		l.memory = vt.memory
	}

	searchBox.Do(func() {
		text := strings.TrimSpace(searchBox.Text())
		if text == "?" {
			w.Info("Searching the lists", strings.Join(query.Help(), "\r\n"))
			return
		}
		q, err := query.Parse(text)
		if err != nil {
			status.SetText("Search not applied: " + sentence(err))
			return
		}
		search = q
		for _, l := range lists {
			l.fill()
		}
		live.refill()
		if book != nil {
			vt.shown(book)
		}
		if q.Empty() {
			status.SetText("The search is cleared. Every list shows all its rows again.")
		} else {
			status.SetText("Every list shows only the rows that match the search.")
		}
	})
	analyst.Do(func() {
		analystMode = analyst.On()
		for _, l := range append(func() []*list {
			var all []*list
			for _, l := range lists {
				all = append(all, l)
			}
			return all
		}(), live.list) {
			if l.picked >= 0 && l.picked < len(l.shown) {
				l.pick(l.picked)
			}
		}
		if analystMode {
			status.SetText("Analyst mode: a row's details end with the exact evidence, times in UTC, and the numbers of rules and ATT&CK techniques.")
		} else {
			status.SetText("Analyst mode is off.")
		}
	})

	// lay sets every list out from a book: its heading, its columns and its
	// rows. While waiting for the first look only the first two are shown.
	lay := func(b *view.Book, waiting bool) {
		for index, page := range map[int]*view.Page{pageProtection: &b.Protection, pageStartup: &b.Startup, pageRunning: &b.Running, pageConnections: &b.Connections, pageAccounts: &b.Accounts, pageHealth: &b.Health, pageWorth: &b.Worth, pageVirusTotal: &b.VirusTotal, pageWallets: &b.Wallets, pageTimeline: &b.Timeline, pageDefences: &b.Defences, pageDevices: &b.Devices} {
			l := lists[index]
			l.page, l.waiting = page, waiting
			if waiting {
				l.page = &view.Page{Name: page.Name, Title: page.Title, Intro: page.Intro, Columns: page.Columns}
			}
			pageTexts[index][0].SetText(page.Title)
			pageTexts[index][1].SetText(page.Intro)
			columns := make([]winui.Column, len(page.Columns))
			for i, column := range page.Columns {
				columns[i] = winui.Column{Title: column.Title, Width: column.Width}
			}
			l.table.SetColumns(columns)
			l.fill()
		}
	}

	// show puts a finished look on every page.
	show := func(b *view.Book) {
		book = b
		if b.Compared != "" {
			summary.SetText(b.Summary + "\r\n" + b.Compared)
		} else {
			summary.SetText(b.Summary)
		}
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
			note += fmt.Sprintf("\r\nWithout administrator rights, %d things could not be read. They are listed under 08 Worth a look.", unseen)
		}
		about.SetText(note)
		// With the rights already held there is nothing more to ask for, and
		// the button says so.
		if b.Snapshot.Elevated {
			raise.SetText("Running as administrator")
		}
		raise.Enable(!b.Snapshot.Elevated && !demo)
		lay(b, false)
		nav[pageWorth].SetText(fmt.Sprintf("08  Worth a look (%d)", len(b.Findings)))
		vt.shown(b)
	}
	vt.reshow = show
	wp.reshow = show
	// Until the first look comes back, every list has its heading and its
	// columns and says that it is waiting.
	lay(view.Build(&model.Snapshot{}, nil), true)

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
			// A fault of LazaScope's own while looking must end in words on
			// the screen, not in a window that vanishes.
			defer func() {
				if fault := recover(); fault != nil {
					w.Post(func() {
						busy = false
						for _, c := range jobs {
							c.Enable(true)
						}
						status.SetText("The look stopped on an error inside LazaScope. Nothing on this PC was changed.")
						w.Alert("LazaScope", fmt.Sprintf("LazaScope ran into an error of its own while looking at this PC, and stopped.\r\n\r\n%v\r\n\r\nNothing on this PC was changed. You can try Look again. If it happens every time, please report it with the line above.", fault))
					})
				}
			}()
			var s *model.Snapshot
			var findings []rules.Finding
			if demo {
				s = sample.PC()
				findings = rules.Check(s)
			} else {
				s = scan.Run(scan.Everything, func(stage string) { w.Post(func() { status.SetText(stage) }) })
				findings = scan.Judge(s)
			}
			b := view.Build(s, findings)
			w.Post(func() {
				// A new look starts with the fingerprints it worked out itself:
				// a file may have changed since the last one.
				clear(prints)
				for path, print := range s.Fingerprints {
					prints[path] = print
				}
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
				vt.afterLook(b)
			})
		}()
	}
	again.Do(look)

	// Compare with a report... holds the look on show against a report that
	// was saved earlier as data, and marks what is new.
	against.Do(func() {
		const title = "Compare with a report"
		if book == nil || busy {
			return
		}
		if demo {
			w.Info(title, "This is the made-up PC, which has no earlier report. On your own PC, save a report as data (.json) today, and compare with it another day to see what has changed.")
			return
		}
		path, err := w.FileDialog("Choose a report that was saved as data", "LazaScope report saved as data (*.json)\x00*.json\x00\x00", "json", "", false)
		if err != nil {
			w.Alert(title, err.Error())
			return
		}
		if path == "" {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			w.Alert(title, "The report could not be opened: "+sentence(err))
			return
		}
		then, err := report.Load(data)
		if err != nil {
			w.Alert(title, sentence(err)+" Only a report saved as data can be compared with: choose Data for other tools when you save one.")
			return
		}
		s := book.Snapshot
		for i := range s.Startup {
			s.Startup[i].New = false
		}
		for i := range s.Processes {
			s.Processes[i].New = false
		}
		for i := range s.Connections {
			s.Connections[i].New = false
		}
		compare.Mark(s, then, "the report of "+then.Taken.Format("2 January 2006 at 15:04"))
		b := view.Build(s, book.Findings)
		show(b)
		text := b.Compared
		if then.Computer != "" && !strings.EqualFold(then.Computer, s.Computer) {
			text += "\r\n\r\nThat report is of another PC, " + then.Computer + ", so much shows as new for that reason alone."
		}
		if len(b.Changes) > 0 {
			text += "\r\n\r\nWhat has changed or gone:"
			for i, line := range b.Changes {
				if i == 12 {
					text += fmt.Sprintf("\r\n\r\nAnd %d more. Save a report to read them all.", len(b.Changes)-i)
					break
				}
				text += "\r\n\r\n" + line
			}
		}
		status.SetText("Compared. In the lists, choose the view What is new to see what was not there before.")
		w.Info(title, text+"\r\n\r\nWhat is new is marked New in the lists. Choose the view What is new above a list to see only that.")
	})

	// Watch for a minute keeps looking, so that a program which starts,
	// sends something and is gone again is still seen. Pressed again, it
	// stops the watch early.
	var halt chan struct{}
	watch.Do(func() {
		if halt != nil {
			close(halt)
			halt = nil
			watch.Enable(false) // until the watch has wound up
			return
		}
		if busy {
			return
		}
		if demo {
			w.Info("Watch for a minute", "This is the made-up PC, where nothing runs. On your own PC this keeps looking for a minute and lists every program that started and every connection that was opened in that time, also the ones that are gone again by the end.")
			return
		}
		busy = true
		for _, c := range jobs {
			c.Enable(false)
		}
		halt = make(chan struct{})
		stop := halt
		watch.SetText("Stop watching")
		status.SetText("Watching this PC for a minute...")
		go func() {
			defer func() {
				if fault := recover(); fault != nil {
					w.Post(func() {
						busy, halt = false, nil
						for _, c := range jobs {
							c.Enable(true)
						}
						watch.SetText("Watch for a minute")
						watch.Enable(true)
						status.SetText("The watch stopped on an error inside LazaScope. Nothing on this PC was changed.")
						w.Alert("LazaScope", fmt.Sprintf("LazaScope ran into an error of its own while watching, and stopped.\r\n\r\n%v\r\n\r\nNothing on this PC was changed.", fault))
					})
				}
			}()
			s := scan.Watch(time.Minute, stop, func(stage string) { w.Post(func() { status.SetText(stage) }) })
			findings := scan.Judge(s)
			b := view.Build(s, findings)
			w.Post(func() {
				clear(prints)
				for path, print := range s.Fingerprints {
					prints[path] = print
				}
				busy, halt = false, nil
				for _, c := range jobs {
					c.Enable(true)
				}
				watch.SetText("Watch for a minute")
				watch.Enable(true)
				show(b)
				status.SetText("Watched. Under 04 Running and 05 Connections, choose the view What is new to see what came and went. Nothing was changed.")
				vt.afterLook(b)
			})
		}()
	})
	raise.Do(func() {
		self, err := os.Executable()
		if err != nil {
			w.Alert("Look again as administrator", "LazaScope could not find its own file to start again.")
			return
		}
		// Windows asks before giving the rights. On a no, this window stays
		// and says what happened.
		arguments := ""
		if place := os.Getenv("LAZASCOPE_PLACE"); place != "" && !strings.ContainsAny(place, " \"") {
			arguments = "--place=" + place
		}
		if w.Elevated(self, arguments) {
			w.Close()
		} else {
			status.SetText("Windows did not start LazaScope as administrator. Nothing has changed, and this look is still the one shown.")
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
		content, err := report.Render(b, lazascope.Version(), path)
		if err != nil {
			w.Alert("Save the report", sentence(err)+" Choose one of the three kinds in the list at the foot of the Save window.")
			return
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
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

// headless takes a look and writes the report with no window.
func headless(path string, demo bool) (code int) {
	// With no window, a message box is the only place left to say that
	// something went wrong.
	defer func() {
		if fault := recover(); fault != nil {
			winui.Fatal("LazaScope", fmt.Errorf("LazaScope ran into an error of its own and wrote no report (%v). Nothing on this PC was changed", fault))
			code = 3
		}
	}()
	if err := report.Fits(path); err != nil {
		winui.Fatal("LazaScope", err)
		return 2
	}
	var s *model.Snapshot
	var findings []rules.Finding
	if demo {
		s = sample.PC()
		findings = rules.Check(s)
	} else {
		s = scan.Run(scan.Everything, nil)
		findings = scan.Judge(s)
	}
	b := view.Build(s, findings)
	content, err := report.Render(b, lazascope.Version(), path)
	if err == nil {
		err = os.WriteFile(path, content, 0600)
	}
	if err != nil {
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
