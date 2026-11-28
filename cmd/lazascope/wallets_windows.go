//go:build windows

package main

import (
	"errors"
	"fmt"
	"lazascope/internal/i18n"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/clipboard"
	"lazascope/internal/files"
	"lazascope/internal/model"
	"lazascope/internal/phrase"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/view"
	"lazascope/internal/virustotal"
	"lazascope/internal/winui"
)

// walletPanel is the Wallets page: the wallets found, the address-swap
// test, the check of a downloaded wallet against the fingerprint its maker
// publishes, and the search for recovery phrases written in files.
type walletPanel struct {
	w      *winui.Window
	status *winui.Control
	demo   bool

	list              *list
	test, print, find *winui.Control
	testing           bool
	stop              chan struct{} // closed to stop the search for phrases; nil when none runs

	book   func() *view.Book
	busy   func() bool
	reshow func(b *view.Book)
}

func newWallets(w *winui.Window, status *winui.Control, demo bool, prints map[string]string) *walletPanel {
	p := &walletPanel{w: w, status: status, demo: demo}
	w.Page(pageWallets)
	heading := w.Heading("", left, 166, across, 30)
	intro := w.Label("", left, 200, across, 42)
	p.test = w.Button(i18n.T("Test for address swapping"), left, 250, 232, 34, p.swapTest)
	p.test.Lead(true)
	p.print = w.Input("", left+242, 250, 240, 34, nil)
	p.print.Hint(i18n.T("Paste the maker's SHA-256"))
	w.Button(i18n.T("Check a download..."), left+492, 250, 170, 34, p.checkDownload)
	p.find = w.Button(i18n.T("Find recovery phrases..."), left+672, 250, 214, 34, p.findPhrases)
	count := w.Caption("", left+896, 250, across-896, 34)
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
	title := i18n.T("Test for address swapping")
	if p.testing {
		return
	}
	if p.demo {
		p.w.Info(title, i18n.T("This is the made-up PC. On your own PC, this copies made-up wallet addresses for a few seconds and watches whether any program swaps them for another."))
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
		i18n.T("The made-up addresses have broken checksums, so no wallet would send coins to them even if one were pasted, and Windows is told to keep them out of the clipboard history. Afterwards LazaScope puts back the text that is on the clipboard now.")
	if saved.HadOther {
		text += "\r\n\r\nThe clipboard holds a picture or files at the moment. Those cannot be put back: copy them again afterwards if you need them."
	}
	if !p.w.Ask(title, text+"\r\n\r\nRun the test now? It takes about seven seconds.") {
		return
	}
	p.testing = true
	p.test.Enable(false)
	p.status.SetText(i18n.T("Testing for address swapping. Please leave the clipboard alone for a few seconds..."))
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
				p.status.SetText(i18n.T("The test could not run: ") + sentence(err))
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
				who := i18n.T("Windows could not say which program did it.")
				if result.By != "" {
					who = i18n.T("Windows says the clipboard was last changed by ") + result.By + "."
				}
				p.status.SetText(i18n.T("A program swapped a copied wallet address. See 08 Worth a look."))
				p.w.Alert(title, i18n.T("A program swapped the made-up ")+result.Kind+" address for another:\r\n\r\n"+result.Into+"\r\n\r\n"+who+
					"\r\n\r\nDo not send coins from this PC until it is cleaned. The finding is under 08 Worth a look.")
				return
			}
			p.status.SetText(i18n.T("No program swapped the made-up addresses. The clipboard's text is back as it was."))
			p.w.Info(title, i18n.T("No program swapped any of the ")+strconv.Itoa(len(result.Tried))+" made-up addresses ("+strings.Join(result.Tried, ", ")+").\r\n\r\n"+
				i18n.T("That is good news, though not a promise: some malware waits, or only swaps addresses of other coins. Whenever you paste an address, check it character by character against the one you meant."))
		})
	}()
}

// checkDownload compares a downloaded file with the fingerprint its maker
// publishes.
func (p *walletPanel) checkDownload() {
	title := i18n.T("Check a download")
	want := strings.ToLower(strings.Join(strings.Fields(p.print.Text()), ""))
	if !virustotal.ValidHash(want) {
		p.w.Info(title, i18n.T("Paste the fingerprint into the box first. A wallet's maker publishes a fingerprint (SHA-256) for each download on its own website: 64 letters and digits. Then choose Check a download... and pick the file you downloaded."))
		return
	}
	path, err := p.w.FileDialog(i18n.T("Choose the downloaded file"), "Programs and installers (*.exe;*.msi;*.msix;*.zip)\x00*.exe;*.msi;*.msix;*.zip\x00All files (*.*)\x00*.*\x00\x00", "", "", false)
	if err != nil {
		p.w.Alert(title, err.Error())
		return
	}
	if path == "" {
		return
	}
	p.status.SetText(i18n.T("Working out the fingerprint of ") + path + "...")
	go func() {
		print, err := files.Fingerprint(path)
		library := files.Open()
		file := library.Look(path)
		library.Close()
		p.w.Post(func() {
			if err != nil {
				p.status.SetText(i18n.T("The file could not be read."))
				p.w.Alert(title, i18n.T("The file could not be read: ")+sentence(err))
				return
			}
			signature := ""
			if file.Program {
				signature = "\r\n\r\nIts signature: " + rules.Signature(file) + "."
			}
			if print == want {
				p.status.SetText(i18n.T("The fingerprints match: this is the file the maker published."))
				p.w.Info(title, "The fingerprints match.\r\n\r\n"+path+"\r\n\r\nThis is exactly the file the maker published, byte for byte."+signature)
				return
			}
			p.status.SetText(i18n.T("The fingerprints do not match. Do not open the file."))
			p.w.Alert(title, fmt.Sprintf("The fingerprints do not match.\r\n\r\nPublished: %s\r\nThis file: %s\r\n\r\n%s\r\n\r\nThis is not the file the maker published, or the fingerprint was copied from the wrong place. Do not install or open it. Download it again from the maker's own website, and check again.%s", want, print, path, signature))
		})
	}()
}

// findPhrases searches the folders where people keep notes for recovery
// phrases written in files, after saying what it reads. While it runs, the
// same button stops it.
func (p *walletPanel) findPhrases() {
	title := i18n.T("Find recovery phrases")
	if p.stop != nil {
		close(p.stop)
		p.stop = nil
		p.find.Enable(false) // until the search has wound down
		p.status.SetText(i18n.T("Stopping the search..."))
		return
	}
	b := p.book()
	if b == nil || p.busy() {
		return
	}
	if p.demo {
		p.w.Info(title, "This is the made-up PC, so LazaScope shows what a search could find there.\r\n\r\nOn your own PC, this reads the text files and documents in your Desktop, Documents and Downloads folders and looks for recovery phrases, without ever showing the words.")
		b.Snapshot.Phrases = sample.Phrases()
		p.reshow(view.Build(b.Snapshot, b.Findings))
		p.status.SetText(i18n.T("The made-up PC: a recovery phrase in one file, and recovery words in another."))
		return
	}
	places := phrase.Places()
	if len(places) == 0 {
		p.w.Alert(title, i18n.T("Windows did not say where this account's Desktop, Documents and Downloads folders are, so there is nowhere to search."))
		return
	}
	text := "A recovery phrase is the 12 to 24 words a cryptocurrency wallet gives you to write down. Whoever has them has the wallet's coins, so a phrase saved in a file can be taken by any program that reads the file.\r\n\r\n" +
		"LazaScope will read the text files and documents in:\r\n\r\n" + strings.Join(places, "\r\n") + "\r\n\r\n" +
		"It looks for 12 or more words in a row from the list that phrases are made from, and checks whether they make a complete phrase. It only reads. It never shows, keeps or sends the words: it notes only the file and the line.\r\n\r\n" +
		"Files kept only in OneDrive are left unread, as reading them would download them, and so are folders of program code such as node_modules.\r\n\r\nSearch now? On a full disk it can take a minute or two, and you can stop it."
	if !p.w.Ask(title, text) {
		return
	}
	stop := make(chan struct{})
	p.stop = stop
	p.find.SetText(i18n.T("Stop the search"))
	p.status.SetText(i18n.T("Searching for recovery phrases..."))
	go func() {
		result := phrase.Search(places, stop, func(read int) {
			p.w.Post(func() {
				if p.stop == stop {
					p.status.SetText(i18n.T("Searching for recovery phrases: ") + fileCount(read) + " read so far...")
				}
			})
		})
		p.w.Post(func() {
			if p.stop == stop {
				p.stop = nil
			}
			p.find.SetText(i18n.T("Find recovery phrases..."))
			p.find.Enable(true)
			b := p.book()
			if b == nil {
				return
			}
			if p.busy() {
				// A new look is on its way and will replace this one.
				p.status.SetText(i18n.T("The search ended while LazaScope was looking at the PC again. Search again to see what it finds."))
				return
			}
			b.Snapshot.Phrases = &result
			p.reshow(view.Build(b.Snapshot, b.Findings))
			p.phrasesFound(title, result)
		})
	}()
}

// phrasesFound says what the search for recovery phrases found.
func (p *walletPanel) phrasesFound(title string, result model.PhraseSearch) {
	var phrases, others []string
	for _, f := range result.Found {
		switch {
		case f.Phrase > 0 || f.Named && !f.List:
			phrases = append(phrases, f.Path)
		case !f.List:
			others = append(others, f.Path)
		}
	}
	read := fileCount(result.Read) + " read"
	if result.Stopped {
		read += ", stopped before the end"
	}
	// A search that did not read every file gives only part of the answer.
	part := ""
	if result.Stopped || result.Full {
		part = "\r\n\r\nThe search did not read every file, so there may be more."
	}
	switch {
	case len(phrases) > 0:
		p.status.SetText(fmt.Sprintf(i18n.T("Found what is very likely a recovery phrase in %s (%s). See the rows above."), fileCount(len(phrases)), read))
		text := "LazaScope found what is very likely a recovery phrase in:\r\n\r\n" + strings.Join(phrases, "\r\n") + "\r\n\r\n" +
			i18n.T("Whoever has a phrase has the wallet's coins. If a phrase belongs to a wallet that holds coins, make a new wallet on a device you trust, move the coins into it, and only then delete the file and empty the Recycle Bin. If it is a test phrase that never held coins, there is nothing to move.")
		if len(others) == 1 {
			text += "\r\n\r\nOne more file holds a run of recovery words that LazaScope could not confirm as a phrase. It is on the list too."
		} else if len(others) > 1 {
			text += fmt.Sprintf("\r\n\r\n%d more files hold runs of recovery words that LazaScope could not confirm as a phrase. They are on the list too.", len(others))
		}
		p.w.Alert(title, text+part+"\r\n\r\nThe words were not shown, kept or sent. Select a row on the Wallets page to read more.")
	case len(others) > 0:
		p.status.SetText(fmt.Sprintf(i18n.T("Found recovery words in %s, not confirmed as a phrase (%s). See the rows above."), fileCount(len(others)), read))
		p.w.Info(title, "No complete recovery phrase was found, but 12 or more words in a row from the list phrases are made from are in:\r\n\r\n"+strings.Join(others, "\r\n")+
			"\r\n\r\nIt may be a phrase written down with a slip or in another order, part of one, an example phrase, or something else. Open the file and see."+part)
	default:
		p.status.SetText(fmt.Sprintf(i18n.T("No recovery phrase found (%s)."), read))
		text := fmt.Sprintf(i18n.T("No recovery phrase was found in the %s read."), fileCount(result.Read))
		p.w.Info(title, text+part+"\r\n\r\nA phrase can still hide where this search does not look: in a photo or a screenshot, a PDF, an email, a password manager, or written in another language. The safest place for a phrase is on paper, kept somewhere safe.")
	}
}

// fileCount writes a number of files, as "1 file" or "1,873 files".
func fileCount(n int) string {
	if n == 1 {
		return "1 file"
	}
	text := strconv.Itoa(n)
	for i := len(text) - 3; i > 0; i -= 3 {
		text = text[:i] + "," + text[i:]
	}
	return text + " files"
}
