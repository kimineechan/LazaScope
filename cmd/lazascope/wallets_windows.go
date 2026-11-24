//go:build windows

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/clipboard"
	"lazascope/internal/files"
	"lazascope/internal/rules"
	"lazascope/internal/view"
	"lazascope/internal/virustotal"
	"lazascope/internal/winui"
)

// walletPanel is the Wallets page: the wallets found, the address-swap
// test, and the check of a downloaded wallet against the fingerprint its
// maker publishes.
type walletPanel struct {
	w      *winui.Window
	status *winui.Control
	demo   bool

	list        *list
	test, print *winui.Control
	testing     bool

	book   func() *view.Book
	busy   func() bool
	reshow func(b *view.Book)
}

func newWallets(w *winui.Window, status *winui.Control, demo bool, prints map[string]string) *walletPanel {
	p := &walletPanel{w: w, status: status, demo: demo}
	w.Page(pageWallets)
	heading := w.Heading("", left, 166, across, 30)
	intro := w.Label("", left, 200, across, 42)
	p.test = w.Button("Test for address swapping", left, 250, 250, 34, p.swapTest)
	p.test.Lead(true)
	p.print = w.Input("", left+262, 250, 470, 34, nil)
	p.print.Hint("Paste the fingerprint (SHA-256) the wallet's maker publishes")
	w.Button("Check a download...", left+744, 250, 190, 34, p.checkDownload)
	count := w.Caption("", left+946, 250, across-946, 34)
	l := &list{picked: -1, prints: prints, count: count}
	l.table = w.Table(left, 292, across, 244, []winui.Column{{Title: ""}}, func(row int) { l.pick(row) })
	l.detail = w.Reader(left, 544, across, 168)
	l.page = &view.Page{}
	p.list = l
	pageTexts[pageWallets] = [2]*winui.Control{heading, intro}
	return p
}

// swapTest copies made-up wallet addresses and watches whether a program
// swaps them, after saying what it is about to do.
func (p *walletPanel) swapTest() {
	const title = "Test for address swapping"
	if p.testing {
		return
	}
	if p.demo {
		p.w.Info(title, "This is the made-up PC. On your own PC, this copies made-up wallet addresses for a few seconds and watches whether any program swaps them for another.")
		return
	}
	if b := p.book(); b == nil || p.busy() {
		return
	}
	saved, err := clipboard.Look(p.w.Handle)
	if err != nil {
		p.w.Alert(title, sentence(err))
		return
	}
	text := "Some malware watches for a copied wallet address and puts a thief's address in its place. This test copies three made-up addresses, one at a time, and watches for two seconds each whether anything changes them.\r\n\r\n" +
		"The made-up addresses have broken checksums, so no wallet would send coins to them even if one were pasted, and Windows is told to keep them out of the clipboard history. Afterwards LazaScope puts back the text that is on the clipboard now."
	if saved.HadOther {
		text += "\r\n\r\nThe clipboard holds a picture or files at the moment. Those cannot be put back: copy them again afterwards if you need them."
	}
	if !p.w.Ask(title, text+"\r\n\r\nRun the test now? It takes about seven seconds.") {
		return
	}
	p.testing = true
	p.test.Enable(false)
	p.status.SetText("Testing for address swapping. Please leave the clipboard alone for a few seconds...")
	go func() {
		result, err := clipboard.Test(p.w.Handle, 2*time.Second)
		p.w.Post(func() {
			p.testing = false
			p.test.Enable(true)
			if errors.Is(err, clipboard.ErrNotRestored) {
				// The test itself ran; say what it found, then this.
				defer p.w.Alert(title, sentence(err))
				err = nil
			}
			if err != nil {
				p.status.SetText("The test could not run: " + sentence(err))
				p.w.Alert(title, sentence(err))
				return
			}
			b := p.book()
			if b == nil {
				return
			}
			s := b.Snapshot
			if result.PID != 0 {
				result.By = "process " + strconv.Itoa(int(result.PID))
				for _, proc := range s.Processes {
					if proc.PID == result.PID {
						result.By, result.Path = proc.Name, proc.File.Path
					}
				}
			}
			s.SwapTest = &result
			if !p.busy() {
				p.reshow(view.Build(s, rules.Check(s)))
			}
			if result.Swapped {
				who := "Windows could not say which program did it."
				if result.By != "" {
					who = "Windows says the clipboard was last changed by " + result.By + "."
				}
				p.status.SetText("A program swapped a copied wallet address. See 08 Worth a look.")
				p.w.Alert(title, "A program swapped the made-up "+result.Kind+" address for another:\r\n\r\n"+result.Into+"\r\n\r\n"+who+
					"\r\n\r\nDo not send coins from this PC until it is cleaned. The finding is under 08 Worth a look.")
				return
			}
			p.status.SetText("No program swapped the made-up addresses. The clipboard's text is back as it was.")
			p.w.Info(title, "No program swapped any of the "+strconv.Itoa(len(result.Tried))+" made-up addresses ("+strings.Join(result.Tried, ", ")+").\r\n\r\n"+
				"That is good news, though not a promise: some malware waits, or only swaps addresses of other coins. Whenever you paste an address, check it character by character against the one you meant.")
		})
	}()
}

// checkDownload compares a downloaded file with the fingerprint its maker
// publishes.
func (p *walletPanel) checkDownload() {
	const title = "Check a download"
	want := strings.ToLower(strings.Join(strings.Fields(p.print.Text()), ""))
	if !virustotal.ValidHash(want) {
		p.w.Info(title, "Paste the fingerprint into the box first. A wallet's maker publishes a fingerprint (SHA-256) for each download on its own website: 64 letters and digits. Then choose Check a download... and pick the file you downloaded.")
		return
	}
	path, err := p.w.FileDialog("Choose the downloaded file", "Programs and installers (*.exe;*.msi;*.msix;*.zip)\x00*.exe;*.msi;*.msix;*.zip\x00All files (*.*)\x00*.*\x00\x00", "", "", false)
	if err != nil {
		p.w.Alert(title, err.Error())
		return
	}
	if path == "" {
		return
	}
	p.status.SetText("Working out the fingerprint of " + path + "...")
	go func() {
		print, err := files.Fingerprint(path)
		library := files.Open()
		file := library.Look(path)
		library.Close()
		p.w.Post(func() {
			if err != nil {
				p.status.SetText("The file could not be read.")
				p.w.Alert(title, "The file could not be read: "+sentence(err))
				return
			}
			signature := ""
			if file.Program {
				signature = "\r\n\r\nIts signature: " + rules.Signature(file) + "."
			}
			if print == want {
				p.status.SetText("The fingerprints match: this is the file the maker published.")
				p.w.Info(title, "The fingerprints match.\r\n\r\n"+path+"\r\n\r\nThis is exactly the file the maker published, byte for byte."+signature)
				return
			}
			p.status.SetText("The fingerprints do not match. Do not open the file.")
			p.w.Alert(title, fmt.Sprintf("The fingerprints do not match.\r\n\r\nPublished: %s\r\nThis file: %s\r\n\r\n%s\r\n\r\nThis is not the file the maker published, or the fingerprint was copied from the wrong place. Do not install or open it. Download it again from the maker's own website, and check again.%s", want, print, path, signature))
		})
	}()
}
