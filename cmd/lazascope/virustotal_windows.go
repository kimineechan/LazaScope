//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"lazascope/internal/files"
	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/view"
	"lazascope/internal/virustotal"
	"lazascope/internal/winui"
)

// emptyFile is the fingerprint of a file with nothing in it. A new key is
// checked by asking about it, which tells VirusTotal nothing about the PC.
const emptyFile = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// vtPanel is the VirusTotal page, with everything that asks VirusTotal.
//
// VirusTotal is asked only with a key the person set up themselves, and
// only when they ask: with the button on this page, with Look up file...,
// or after each look once they switch that on. Each lookup sends a file's
// fingerprint and the key, never the file.
type vtPanel struct {
	w      *winui.Window
	status *winui.Control
	demo   bool

	memory *virustotal.Memory
	client *virustotal.Client // nil until a key is saved
	broken string             // why a saved key could not be opened, if it could not

	list                             *list
	keyBox, keyState, ask, afterEach *winui.Control

	stop context.CancelFunc // set while a run of lookups goes on

	book   func() *view.Book
	busy   func() bool
	reshow func(b *view.Book)
}

// newVirusTotal sets up the VirusTotal page, and opens the key and the
// memory of earlier answers, if there are any.
func newVirusTotal(w *winui.Window, status *winui.Control, demo bool, prints map[string]string) *vtPanel {
	v := &vtPanel{w: w, status: status, demo: demo}
	path, err := virustotal.MemoryPath()
	if err != nil || demo {
		path = "" // the made-up PC keeps nothing
	}
	v.memory = virustotal.OpenMemory(path)
	if !demo {
		switch key, err := virustotal.LoadKey(); {
		case err == nil:
			v.client, _ = virustotal.New(key)
		case !errors.Is(err, virustotal.ErrNoKey):
			v.broken = sentence(err)
		}
	}

	w.Page(pageVirusTotal)
	heading := w.Heading("", left, 166, across, 30)
	intro := w.Label("", left, 200, across, 42)
	v.keyBox = w.Input("", left, 250, 360, 34, nil)
	v.keyBox.Secret()
	w.Button("Save key", left+372, 250, 118, 34, v.saveKey)
	w.Button("Forget", left+502, 250, 104, 34, v.forget)
	v.keyState = w.Caption("", left+618, 250, across-618, 34)
	v.ask = w.Button("Ask VirusTotal now", left, 294, 220, 34, v.score)
	v.ask.Lead(true)
	v.afterEach = w.Switch("Also after each look", left+232, 294, 250, 34, v.switchAfterEach)
	v.afterEach.Turn(v.memory.AfterEachLook())
	count := w.Caption("", left+494, 294, across-494-240, 34)
	w.Button("Open VirusTotal's page", left+across-228, 294, 228, 34, v.openPage)
	l := &list{picked: -1, prints: prints, memory: v.memory, count: count}
	l.table = w.Table(left, 338, across, 198, []winui.Column{{Title: ""}}, func(row int) { l.pick(row) })
	l.detail = w.Reader(left, 544, across, 168)
	l.page = &view.Page{}
	v.list = l
	pageTexts[pageVirusTotal] = [2]*winui.Control{heading, intro}
	v.showKey()
	return v
}

// showKey says on the page whether a key is saved.
func (v *vtPanel) showKey() {
	switch {
	case v.demo:
		v.keyState.SetText("The made-up PC: its answers are made up too.")
	case v.client != nil:
		v.keyState.SetText("A key ending in " + v.client.Ends() + " is saved for your Windows account.")
	case v.broken != "":
		v.keyState.SetText("The saved key could not be opened. Save it again.")
	default:
		v.keyState.SetText("No key saved, so nothing is sent to VirusTotal.")
	}
}

// shown brings the page up to date with a look that is now on show.
func (v *vtPanel) shown(b *view.Book) {
	l := v.list
	asked, flagged, unknown := 0, 0, 0
	for _, row := range l.page.Rows {
		switch row.Cells[0] {
		case "Not asked yet":
		case "Not known":
			asked++
			unknown++
		default:
			asked++
			if !strings.HasPrefix(row.Cells[0], "0 of") && row.Cells[0] != "No verdicts" {
				flagged++
			}
		}
	}
	text := fmt.Sprintf("%d files. %d asked about", len(l.page.Rows), asked)
	if asked > 0 {
		text += fmt.Sprintf(": %d flagged, %d not known", flagged, unknown)
	}
	if search.Empty() { // a search says how many rows match instead
		l.count.SetText(text + ".")
	}
	if v.client == nil && !v.demo {
		v.explain()
	}
}

// explain fills the box of detail with how to set VirusTotal up, and what
// that means.
func (v *vtPanel) explain() {
	lines := []view.Line{
		{Style: view.Heading, Text: "How to set up VirusTotal"},
		{Style: view.Text, Text: "1. Make a free account at virustotal.com, and open the link VirusTotal sends by email."},
		{Style: view.Text, Text: "2. Open your account's menu at the top right of VirusTotal's website and choose API key. Copy the key."},
		{Style: view.Text, Text: "3. Click in the box above, press Ctrl + V to paste the key, and choose Save key."},
		{Style: view.Heading, Text: "What is sent, and when"},
		{Style: view.Text, Text: "Nothing, until you choose Ask VirusTotal now or Look up file..., or switch on Also after each look. Each lookup then sends VirusTotal a file's fingerprint and your key, never the file itself. VirusTotal learns that your account asked about that file."},
		{Style: view.Text, Text: "A free key may make 4 lookups a minute and 500 a day, for personal use that is not commercial. LazaScope keeps to that pace, and remembers each answer for a week so as not to ask twice."},
		{Style: view.Heading, Text: "Where the key is kept"},
		{Style: view.Text, Text: "In LazaScope's folder inside your own AppData folder, sealed by Windows so that only your Windows account on this PC can open it. Forget removes it, with everything VirusTotal said."},
	}
	if v.broken != "" {
		lines = append(lines, view.Line{Style: view.Heading, Text: "The saved key"}, view.Line{Style: view.Text, Text: v.broken})
	}
	v.list.detail.Read(paragraphs(lines)...)
}

// saveKey checks the key typed in the box with VirusTotal, and keeps it.
func (v *vtPanel) saveKey() {
	const title = "Save the VirusTotal key"
	if v.demo {
		v.w.Info(title, "This is the made-up PC. Start LazaScope without --demo to set up VirusTotal.")
		return
	}
	key, ok := virustotal.CleanKey(v.keyBox.Text())
	if !ok {
		v.w.Alert(title, sentence(virustotal.ErrForm))
		return
	}
	if !v.w.Ask(title, "Save this key, and use it to ask VirusTotal about the files on this PC?\r\n\r\n"+
		"LazaScope keeps the key in your own folder on this PC, sealed by Windows so that only your Windows account can open it.\r\n\r\n"+
		"Nothing is sent until you choose Ask VirusTotal now or Look up file..., or switch on Also after each look. Each lookup sends a file's fingerprint and the key, never the file. VirusTotal learns that your account asked about that file.\r\n\r\n"+
		"To check the key now, LazaScope asks about the fingerprint of an empty file, which says nothing about this PC.") {
		return
	}
	client, err := virustotal.New(key)
	if err != nil {
		v.w.Alert(title, sentence(err))
		return
	}
	v.status.SetText("Checking the key with VirusTotal...")
	go func() {
		_, err := client.Look(context.Background(), emptyFile)
		v.w.Post(func() {
			if errors.Is(err, virustotal.ErrKey) || errors.Is(err, virustotal.ErrInactive) {
				v.status.SetText("The key was not saved.")
				v.w.Alert(title, sentence(err))
				return
			}
			if saveErr := virustotal.SaveKey(key); saveErr != nil {
				v.status.SetText("The key was not saved.")
				v.w.Alert(title, "The key could not be saved: "+sentence(saveErr))
				return
			}
			v.client, v.broken = client, ""
			v.keyBox.SetText("")
			v.showKey()
			if err != nil {
				v.status.SetText("The key is saved. VirusTotal could not check it just now: " + sentence(err))
			} else {
				v.status.SetText("The key works, and is saved for your Windows account. Choose Ask VirusTotal now to look the programs up.")
			}
			v.list.fill()
			v.shown(v.book())
		})
	}()
}

// forget removes the key and everything VirusTotal said.
func (v *vtPanel) forget() {
	const title = "Forget VirusTotal"
	if v.demo {
		v.w.Info(title, "This is the made-up PC, which keeps nothing.")
		return
	}
	if !v.w.Ask(title, "Remove the saved key, and everything VirusTotal said, from this PC?\r\n\r\nYour VirusTotal account is not touched. To use VirusTotal again, save the key again.") {
		return
	}
	if v.stop != nil {
		v.stop()
	}
	keyErr, memoryErr := virustotal.ForgetKey(), v.memory.Forget()
	v.client, v.broken = nil, ""
	v.showKey()
	v.afterEach.Turn(false)
	if b := v.book(); b != nil {
		s := b.Snapshot
		s.VirusTotal = nil
		v.reshow(view.Build(s, rules.Check(s)))
	}
	if err := errors.Join(keyErr, memoryErr); err != nil {
		v.w.Alert(title, "Not everything could be removed: "+sentence(err))
		return
	}
	v.status.SetText("The VirusTotal key and everything VirusTotal said are removed from this PC.")
}

// switchAfterEach keeps the choice to ask about new files after each look.
func (v *vtPanel) switchAfterEach() {
	on := v.afterEach.On()
	if on && v.client == nil {
		v.afterEach.Turn(false)
		v.w.Info("Ask after each look", "Save a VirusTotal key first. The steps are in the box below.")
		return
	}
	v.memory.SetAfterEachLook(on)
	v.memory.Save()
	if on {
		v.status.SetText("After each look, LazaScope will ask VirusTotal about programs it has no answer for yet.")
	} else {
		v.status.SetText("LazaScope will ask VirusTotal only when you choose to.")
	}
}

// score asks VirusTotal about every file on the page, or stops a run that
// is going on.
func (v *vtPanel) score() {
	const title = "Ask VirusTotal"
	if v.stop != nil {
		v.stop()
		return
	}
	switch {
	case v.demo:
		v.w.Info(title, "This is the made-up PC, and its answers are made up. On your own PC, this asks VirusTotal about the programs listed here.")
		return
	case v.client == nil:
		v.w.Info(title, "Save a VirusTotal key first. The steps are in the box below.")
		v.explain()
		return
	}
	b := v.book()
	if b == nil || v.busy() {
		return
	}
	todo := virustotal.Candidates(b.Snapshot, b.Findings)
	if len(todo) == 0 {
		v.w.Info(title, "There is nothing to ask about: every program that starts by itself or runs carries a working signature from Microsoft.")
		return
	}
	v.run(b, todo, false)
}

// afterLook asks about new files after a look, when that is switched on.
func (v *vtPanel) afterLook(b *view.Book) {
	if v.demo || v.client == nil || v.stop != nil || !v.memory.AfterEachLook() {
		return
	}
	if todo := virustotal.Candidates(b.Snapshot, b.Findings); len(todo) > 0 {
		v.run(b, todo, true)
	}
}

// run asks VirusTotal about files, one at a time, at the pace the key
// allows. A file it was asked about in the last week is not asked about
// again. quiet runs, after a look, say what happened in the status line
// only.
func (v *vtPanel) run(b *view.Book, todo []virustotal.Candidate, quiet bool) {
	ctx, cancel := context.WithCancel(context.Background())
	v.stop = cancel
	v.ask.SetText("Stop asking")
	client, memory := v.client, v.memory
	go func() {
		asked, remembered, failed := 0, 0, 0
		var halt error
		for i, c := range todo {
			if ctx.Err() != nil {
				break
			}
			print, ok := memory.Print(c.Path, c.Size, c.Modified)
			if !ok {
				info, err := os.Stat(c.Path)
				if err != nil || info.IsDir() || info.Size() > files.FingerprintLimit {
					failed++
					continue
				}
				if print, err = files.Fingerprint(c.Path); err != nil {
					failed++
					continue
				}
				memory.KeepPrint(c.Path, info.Size(), info.ModTime(), print)
			}
			if r, ok := memory.Answer(print); ok && virustotal.Recent(r, time.Now()) {
				remembered++
				v.w.Post(func() { v.progress(b, c.Path, print, r) })
				continue
			}
			left := (len(todo) - i) * int(virustotal.Pace/time.Second)
			v.w.Post(func() {
				v.status.SetText(fmt.Sprintf("Asking VirusTotal about %s, %d of %d. A free key allows 4 lookups a minute, so this takes up to %s.", c.Name, i+1, len(todo), minutes(left)))
			})
			r, err := client.Look(ctx, print)
			if err != nil {
				if virustotal.Fatal(err) {
					halt = err
					break
				}
				failed++
				continue
			}
			memory.Keep(print, r)
			memory.Save()
			asked++
			v.w.Post(func() { v.progress(b, c.Path, print, r) })
		}
		v.w.Post(func() {
			v.stop = nil
			v.ask.SetText("Ask VirusTotal now")
			v.rejudge()
			text := fmt.Sprintf("VirusTotal: %d files asked about", asked)
			if remembered > 0 {
				text += fmt.Sprintf(", %d answered from the last week", remembered)
			}
			if failed > 0 {
				text += fmt.Sprintf(", %d could not be read or asked about", failed)
			}
			text += ". What it said is in the lists, and anything flagged is under 08 Worth a look."
			switch {
			case errors.Is(halt, context.Canceled):
				v.status.SetText("Stopped. " + text)
			case halt != nil:
				v.status.SetText("Stopped: " + sentence(halt))
				if !quiet {
					v.w.Alert("Ask VirusTotal", sentence(halt)+"\r\n\r\n"+text)
				}
			default:
				v.status.SetText(text)
			}
		})
	}()
}

// minutes says a number of seconds as a short span of time.
func minutes(seconds int) string {
	switch m := (seconds + 59) / 60; {
	case m <= 1:
		return "a minute"
	default:
		return fmt.Sprintf("%d minutes", m)
	}
}

// progress shows an answer on the page as it comes in, while the look the
// run started from is still the one on show.
func (v *vtPanel) progress(b *view.Book, path, print string, r model.Reputation) {
	v.list.prints[strings.ToLower(path)] = print
	if v.book() != b {
		return
	}
	for i, row := range v.list.shown {
		if strings.EqualFold(row.Path, path) {
			v.list.table.SetCell(i, 0, virustotal.Says(r))
		}
	}
}

// rejudge puts what VirusTotal said into the look on show, runs the rules
// again, and shows the result.
func (v *vtPanel) rejudge() {
	b := v.book()
	if b == nil || v.busy() {
		return
	}
	s := b.Snapshot
	v.memory.Apply(s)
	v.reshow(view.Build(s, rules.Check(s)))
}

// openPage offers to open VirusTotal's page for the file chosen in the list.
func (v *vtPanel) openPage() {
	const title = "Open VirusTotal's page"
	l := v.list
	if l.picked < 0 || l.picked >= len(l.shown) {
		v.w.Info(title, "Select a row first.")
		return
	}
	path := l.shown[l.picked].Path
	print := l.prints[strings.ToLower(path)]
	if v.demo {
		v.w.Info(title, "This is the made-up PC, whose fingerprints are made up, so VirusTotal would not know them.")
		return
	}
	if print == "" {
		v.w.Info(title, "LazaScope has not worked out this file's fingerprint yet. Choose Ask VirusTotal now, or Look up file... on the 03 Start-up or 04 Running page.")
		return
	}
	v.offer(path, print)
}

// offer asks before opening VirusTotal's page for a file in the browser.
func (v *vtPanel) offer(path, print string) {
	address := virustotal.Page(print)
	if address == "" {
		return
	}
	said := ""
	if r, ok := v.memory.Answer(print); ok {
		said = "VirusTotal says: " + rules.VirusTotalSays(r) + ".\r\n\r\n"
	}
	if !v.w.Ask("Open VirusTotal's page", said+"Open VirusTotal's page for this file in your browser?\r\n\r\n"+path+"\r\n\r\nYour browser sends VirusTotal the fingerprint, as part of the page's address:\r\n\r\n"+print+"\r\n\r\nThe file itself stays on this PC.") {
		return
	}
	if v.w.Browse(address) {
		v.status.SetText("Opened VirusTotal's page for the file in your browser. Only its fingerprint was sent.")
	} else {
		v.w.Alert("Open VirusTotal's page", "Windows could not open your browser. You can type this address into it yourself:\r\n\r\n"+address)
	}
}

// lookUp asks VirusTotal about one file, for Look up file... on a list. A
// file it has an answer for from the last week offers its page instead.
func (v *vtPanel) lookUp(l *list, path, print string) {
	if r, ok := v.memory.Answer(print); ok && virustotal.Recent(r, time.Now()) {
		v.offer(path, print)
		return
	}
	v.status.SetText("Asking VirusTotal about " + path + "...")
	client := v.client
	go func() {
		r, err := client.Look(context.Background(), print)
		v.w.Post(func() {
			if err != nil {
				v.status.SetText("VirusTotal could not be asked: " + sentence(err))
				v.w.Alert("Look up file", sentence(err))
				return
			}
			v.memory.Keep(print, r)
			v.memory.Save()
			if l.picked >= 0 && l.picked < len(l.shown) && strings.EqualFold(l.shown[l.picked].Path, path) {
				l.pick(l.picked) // the details now say what VirusTotal said
			}
			says := rules.VirusTotalSays(r)
			v.status.SetText("VirusTotal: " + strings.ToUpper(says[:1]) + says[1:] + ". Choose Look up file... again to open its page.")
		})
	}()
}
