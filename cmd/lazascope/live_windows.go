//go:build windows

package main

import (
	"fmt"

	"lazascope/internal/detect"
	"lazascope/internal/query"
	"lazascope/internal/sensor"
	"lazascope/internal/view"
	"lazascope/internal/winui"
)

// livePanel is the live watch: every program that starts, as it starts,
// checked against the detections.
type livePanel struct {
	w       *winui.Window
	status  *winui.Control
	demo    bool
	list    *list
	button  *winui.Control
	choice  *winui.Control
	stop    chan struct{}
	rows    []view.Row
	alerts  int
	started bool
}

func newLive(w *winui.Window, status *winui.Control, demo bool) *livePanel {
	p := &livePanel{w: w, status: status, demo: demo}
	w.Page(pageLive)
	heading := w.Heading("Watch programs start, live", left, 166, across, 30)
	intro := w.Label("Every program that starts while this runs, checked the moment Windows reports it against LazaScope's detections, such as Word starting PowerShell or a command that deletes Windows' backups.", left, 200, across, 42)
	p.button = w.Button("Start watching", left, 250, 180, 34, p.toggle)
	p.button.Lead(true)
	p.choice = w.Choice([]string{"Every program", "Only what set off a detection"}, left+192, 250, 300, 34, p.refill)
	count := w.Caption("Not watching.", left+504, 250, across-504-148, 34)
	w.Button("Copy details", left+across-136, 250, 136, 34, func() {
		if w.Copy(p.list.detail.Words()) {
			status.SetText("Copied the details shown below the list.")
		}
	})
	l := &list{picked: -1, prints: map[string]string{}, count: count}
	columns := make([]winui.Column, len(view.LiveColumns))
	for i, c := range view.LiveColumns {
		columns[i] = winui.Column{Title: c.Title, Width: c.Width}
	}
	l.table = w.Table(left, 292, across, 244, columns, func(row int) { l.pick(row) })
	l.detail = w.Reader(left, 544, across, 168)
	l.page = &view.Page{Name: "Live", Title: heading.Text(), Intro: intro.Text(), Columns: view.LiveColumns}
	p.list = l
	l.detail.Read(paragraphs([]view.Line{
		{Style: view.Heading, Text: "How the watch works"},
		{Style: view.Text, Text: "Choose Start watching. Windows Management Instrumentation, the part of Windows that answers questions about the system, reports each new program, and LazaScope checks it against its 15 detections, listed in docs/DETECTIONS.md. Nothing is changed and nothing is sent anywhere."},
		{Style: view.Text, Text: "Windows reports new programs once a second, so one that starts and ends within the same second can be missed. The command lines of other accounts' programs are given to administrators only."},
		{Style: view.Text, Text: "Choose Only what set off a detection above to see just those. The search box at the top works here too."},
	})...)
	return p
}

// keep reports whether a row is shown, under the view chosen and the search.
func (p *livePanel) keep(row view.Row) bool {
	if p.choice.Chosen() == 1 && row.Level == view.Plain {
		return false
	}
	return search.Match(query.Record{Fields: row.Fields, Text: row.Text})
}

// refill shows the rows again, after the view changed.
func (p *livePanel) refill() {
	l := p.list
	l.shown = l.shown[:0]
	var cells [][]string
	var tints []winui.Colour
	for _, row := range p.rows {
		if p.keep(row) {
			l.shown = append(l.shown, row)
			cells, tints = append(cells, row.Cells), append(tints, tint(row))
		}
	}
	l.table.Fill(cells, tints)
	l.picked = -1
	p.counts()
}

func (p *livePanel) counts() {
	state := "Watching."
	if !p.started {
		state = "Not watching."
	}
	p.list.count.SetText(fmt.Sprintf("%s %d programs started, %d set off a detection.", state, len(p.rows), p.alerts))
}

// toggle starts or stops the watch.
func (p *livePanel) toggle() {
	if p.demo {
		p.w.Info("Watch programs start", "This is the made-up PC, where nothing runs. On your own PC this lists every program that starts while it watches, and checks each against the detections.")
		return
	}
	if p.started {
		close(p.stop)
		p.started = false
		p.button.SetText("Start watching")
		p.counts()
		p.status.SetText("Stopped watching. The list stays until LazaScope is closed.")
		return
	}
	p.stop = make(chan struct{})
	p.started = true
	p.button.SetText("Stop watching")
	p.counts()
	p.status.SetText("Watching programs start. Nothing is changed; LazaScope only reads what Windows reports.")
	stop := p.stop
	go func() {
		err := sensor.Watch(stop, func(e detect.Event) {
			alerts := detect.Check(e)
			row := view.LiveRow(e, alerts)
			p.w.Post(func() {
				if len(p.rows) >= 5000 {
					return // enough for one sitting; stop and start again for more
				}
				p.rows = append(p.rows, row)
				if len(alerts) > 0 {
					p.alerts++
					p.status.SetText(alerts[0].Severity.String() + ": " + alerts[0].Title + " (" + e.Name + ")")
				}
				if p.keep(row) {
					p.list.shown = append(p.list.shown, row)
					p.list.table.Append(row.Cells, tint(row))
				}
				p.counts()
			})
		})
		p.w.Post(func() {
			if err != nil && p.started && p.stop == stop {
				p.started = false
				p.button.SetText("Start watching")
				p.counts()
				p.status.SetText("The watch stopped: " + sentence(err))
			}
		})
	}()
}
