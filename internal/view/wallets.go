package view

import (
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/rules"
)

// wallets lists the cryptocurrency wallets found, and the settings and
// tests that matter for them. It is shown in the window only: a report is
// made to be sent, and a list of someone's wallets is not for sending.
func (b *builder) wallets() Page {
	s := b.s
	page := Page{
		Name: "Wallets", Title: "Cryptocurrency wallets on this PC",
		Intro:   "The wallets LazaScope found: extensions in the browsers, wallet programs, and folders of wallet files. LazaScope only notes where they are. It never opens a wallet, reads a key or sends anything about them anywhere.",
		Columns: []Column{{"Check", 124}, {"Wallet", 210}, {"Kind", 250}, {"Where", 0}},
	}
	for i, w := range s.Wallets {
		row := Row{Ref: "wallet:" + strconv.Itoa(i), Level: Plain}
		kind := w.Kind
		lines := []Line{{Heading, w.Name}}
		switch w.Kind {
		case "Browser extension":
			row.Level = b.worst(w.Ref)
			if w.Verified {
				kind += ", the real one"
				lines = append(lines, Line{Text, "LazaScope checked this extension's number against the one " + w.Name + "'s makers publish, and it matches. It is the real " + w.Name + "."})
				if row.Level == Plain {
					row.Level = Fine
				}
			} else {
				lines = append(lines, Line{Text, "An extension that calls itself a wallet. LazaScope knows the real numbers of only some wallets, so it could not check this one. Check that it came from the wallet maker's own link."})
			}
			lines = b.said(lines, w.Ref)
		case "Program":
			if w.Ref != "" {
				row.Level = b.worst(w.Ref)
			}
			row.Level = max(row.Level, b.worst(rules.FileRef(w.Where)))
			row.Path = w.Where
			lines = append(lines, Line{Text, "A wallet program. It is running now or set to start by itself."}, Line{Text, "File:"}, Line{Command, w.Where})
			lines = b.said(lines, w.Ref, rules.FileRef(w.Where))
		default:
			row.Path = w.Where
			lines = append(lines, Line{Text, "A folder of " + w.Name + "'s files."})
			if w.Keys {
				lines = append(lines, Line{Text, "Files like these can hold the keys to coins, usually locked with the wallet's own password. Whoever copies them can try to open them elsewhere."})
			} else {
				lines = append(lines, Line{Text, w.Name + " is the app of a hardware wallet, which keeps the keys on the device itself. Its files hold the accounts and their history, not the keys."})
			}
			lines = append(lines, Line{Text, "Folder:"}, Line{Command, w.Where})
			if w.Synced != "" {
				kind += ", copied by " + w.Synced
				row.Level = max(row.Level, Look)
				lines = append(lines, Line{Text, w.Synced + " copies this folder off the PC."})
			}
			if w.Keys {
				row.Level = max(row.Level, b.worst("wallets"))
			}
			lines = b.said(lines, "wallets")
		}
		check := row.Level.String()
		if row.Level == Plain {
			check = ""
		}
		row.Cells = []string{check, w.Name, kind, w.Where}
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}

	// The clipboard, and the test for programs that swap a copied address.
	clip := "Not known"
	switch {
	case s.Clipboard.History == model.Yes && s.Clipboard.Cloud == model.Yes:
		clip = "History on, and sent to other devices"
	case s.Clipboard.History == model.Yes:
		clip = "History on"
	case s.Clipboard.History == model.No:
		clip = "History off"
	}
	good := model.NotKnown
	if s.Clipboard.History != model.NotKnown {
		good = model.Say(s.Clipboard.History == model.No)
	}
	page.Rows = append(page.Rows, b.topic("Clipboard", clip, good,
		"With clipboard history on, Windows keeps what is copied, so that Windows key + V can paste it again later. A recovery phrase or a key that was copied stays in that list too.", "clipboard"))
	swap := "Not run. Choose Test for address swapping above."
	swapGood := model.NotKnown
	if t := s.SwapTest; t != nil {
		swap = "Run at " + t.When.Format("15:04") + " with " + strconv.Itoa(len(t.Tried)) + " kinds of address: none was swapped"
		swapGood = model.Yes
		if t.Swapped {
			swap = "A program swapped the " + t.Kind + " address"
			swapGood = model.No
		}
	}
	swapRow := b.topic("Address-swap test", swap, swapGood,
		"Some malware watches for a copied wallet address and puts the thief's in its place. The test copies made-up addresses that no wallet accepts, watches for a few seconds whether anything changes them, and puts back what was on the clipboard.", "swaptest")
	if t := s.SwapTest; t != nil && t.Swapped {
		// The finding is about the program that swapped it, so the row takes its level here.
		swapRow.Level = First
		swapRow.Cells[0] = First.String()
		swapRow.Detail = b.said(swapRow.Detail, rules.ProcessRef(t.PID))
	}
	page.Rows = append(page.Rows, swapRow)
	var clouds []string
	for _, c := range s.Clouds {
		clouds = append(clouds, c.Service+": "+c.Path)
	}
	if len(clouds) == 0 {
		clouds = []string{"None found"}
	}
	page.Rows = append(page.Rows, b.topic("Cloud folders", strings.Join(clouds, "; "), model.Yes,
		"OneDrive, Dropbox and iCloud Drive copy their folders to the internet. Wallet files in them are copied too.", "clouds"))
	for i := range page.Rows[len(page.Rows)-3:] {
		row := &page.Rows[len(page.Rows)-3+i]
		row.Cells = []string{row.Cells[0], row.Cells[1], "Setting", row.Cells[2]}
	}
	return page
}
