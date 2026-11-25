package view

import (
	"fmt"
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/phrase"
	"lazascope/internal/wallets"
)

// The search for recovery phrases in files shows on the Wallets page: a
// row for each file found, and a row for the search itself. Like the rest
// of that page, it is never part of a saved report.

// places names where a file's runs start, as "line 4" or "lines 4, 9 and 30".
func places(f model.PhraseFile) string {
	u := phrase.Unit(f.Path)
	if len(f.Lines) == 1 {
		return u + " " + strconv.Itoa(f.Lines[0])
	}
	var numbers []string
	for i, line := range f.Lines {
		if i == 5 {
			break
		}
		numbers = append(numbers, strconv.Itoa(line))
	}
	more := len(numbers) < f.Runs
	if more {
		return u + "s " + strings.Join(numbers, ", ") + " and others"
	}
	return u + "s " + strings.Join(numbers[:len(numbers)-1], ", ") + " and " + numbers[len(numbers)-1]
}

// odds says how often a run of random words passes a phrase's check.
func odds(words int) string {
	return map[int]string{12: "16", 15: "32", 18: "64", 21: "128", 24: "256"}[words]
}

// phraseRow is a file that holds a run of recovery words.
func (b *builder) phraseRow(i int, f model.PhraseFile) Row {
	row := Row{Ref: "phrase:" + strconv.Itoa(i), Path: f.Path}
	at := places(f)
	where := f.Path + ", " + at
	var name, kind string
	var lines []Line
	start := strings.ToUpper(at[:1]) + at[1:] + " of this file starts "
	if f.Runs > 1 {
		start = fmt.Sprintf("This file has %d runs of such words, starting on %s. The longest is ", f.Runs, at)
	}
	switch {
	case f.List:
		name, kind = "Recovery word list", "The list itself, not a phrase"
		lines = []Line{{Heading, "The recovery word list, not a phrase"},
			{Text, "This file holds the list of 2,048 words that recovery phrases are made from, or part of it, in the list's own order. Wallet programs and the code that makes them carry this list. It is not anyone's phrase, and there is nothing to do."}}
	case f.Phrase > 0 && f.Electrum:
		row.Level = First
		name, kind = "Electrum seed", "In a file"
		lines = []Line{{Heading, "An Electrum recovery seed written in a file"},
			{Text, "Recovery phrases are made from a list of 2,048 words. " + start + fmt.Sprintf("%d of them in a row, and they hold a complete %d-word seed made by the Electrum wallet: Electrum builds a check of its own into its seeds, and random words pass it only about one time in 216.", f.Words, f.Phrase)},
			{Text, "Ordinary writing almost never has 12 words from that list in a row, so this is very likely a real Electrum seed." + named(f)}}
	case f.Phrase > 0:
		row.Level = First
		name, kind = "Recovery phrase", "In a file"
		lines = []Line{{Heading, "A recovery phrase written in a file"},
			{Text, "Recovery phrases are made from a list of 2,048 words. " + start + fmt.Sprintf("%d of them in a row, and they hold a complete %d-word phrase whose check holds: the last word of every phrase is partly a check on the others, and random words pass it only about one time in %s.", f.Words, f.Phrase, odds(f.Phrase))},
			{Text, "Ordinary writing almost never has 12 words from that list in a row, so this is very likely a real recovery phrase." + named(f)}}
	case f.Named:
		row.Level = First
		name, kind = "Recovery phrase", "In a file named like one"
		lines = []Line{{Heading, "Recovery words in a file named like a phrase"},
			{Text, "Recovery phrases are made from a list of 2,048 words. " + start + fmt.Sprintf("%d of them in a row, and the file's name, %s, points to a recovery phrase too.", f.Words, quote(f.Path))},
			{Text, "LazaScope could not confirm a complete phrase with a phrase's own check. It may have been written down with a slip or in another order, or come from a wallet whose check LazaScope does not know. Treat it as a phrase until you have looked."}}
	default:
		row.Level = Look
		name, kind = "Recovery words", "In a file"
		lines = []Line{{Heading, "Words from the recovery list, written in a file"},
			{Text, "Recovery phrases are made from a list of 2,048 words. " + start + fmt.Sprintf("%d of them in a row.", f.Words)},
			{Text, "LazaScope could not confirm them as a complete phrase: they do not pass a phrase's own check, or they repeat words the way a real phrase almost never does. It may be a phrase written down with a slip or in another order, part of one, an example phrase, or text that happens to use these words. Open the file and see."}}
	}
	if !f.List {
		lines = append(lines,
			Line{Text, "Whoever has a wallet's recovery phrase has its coins, from anywhere in the world. Any program that can read this file can read the phrase, and malware that steals passwords looks for files like this one."},
			Line{Heading, "What to do"},
			Line{Text, "If the words are the phrase of a wallet that holds coins, make a new wallet on a device you trust, move the coins into it, and write the new phrase on paper kept somewhere safe. Moving the coins is what counts: the phrase may have been copied already, and deleting the file does not take a copy back. Then delete this file and empty the Recycle Bin."},
			Line{Text, "If it is a test phrase that never held coins, there is nothing to move."})
		if synced := wallets.Synced(f.Path, b.s.Clouds); synced != "" {
			kind = "In a file, copied by " + synced // the copying matters more than the name
			lines = append(lines, Line{Text, synced + " copies this file off the PC, so it is on " + synced + "'s servers too. Delete it there as well, and from " + synced + "'s own recycle bin and the file's earlier versions."})
		}
		lines = append(lines, Line{Aside, "LazaScope did not show, keep or send the words. It noted only the file and the " + phrase.Unit(f.Path) + "."})
	}
	lines = append(lines, Line{Text, "File:"}, Line{Command, f.Path})
	check := row.Level.String()
	if row.Level == Plain {
		check = ""
	}
	row.Cells = []string{check, name, kind, where}
	row.Detail = lines
	return row
}

// named adds that a file's name points to a phrase as well.
func named(f model.PhraseFile) string {
	if !f.Named {
		return ""
	}
	return " Its name, " + quote(f.Path) + ", points to one as well."
}

// quote gives a file's name, without its folders, in quotation marks.
func quote(path string) string {
	return "\u201c" + path[strings.LastIndexAny(path, `\/`)+1:] + "\u201d"
}

// likely reports whether a file very likely holds a recovery phrase: a
// complete one, or a run of its words in a file named like one.
func likely(f model.PhraseFile) bool { return f.Phrase > 0 || f.Named && !f.List }

// phraseTopic is the row for the search itself: whether it has run, what
// it read and what it could not.
func (b *builder) phraseTopic() Row {
	p := b.s.Phrases
	about := "Whoever has a wallet's recovery phrase has its coins, so a phrase saved in a file can be taken by any program that reads the file. The search reads the text files and documents in the folders where people keep notes, and looks for 12 or more words in a row from the list phrases are made from. It notes only the file and the line, never the words."
	if p == nil {
		return b.topic("Recovery phrases in files", "Not searched. Choose Find recovery phrases above.", model.NotKnown, about, "phrases")
	}
	phrases, others := 0, 0
	for _, f := range p.Found {
		switch {
		case likely(f):
			phrases++
		case !f.List:
			others++
		}
	}
	state := fmt.Sprintf("Searched %s at %s: none found", several(p.Read, "file", "files"), p.When.Format("15:04"))
	switch {
	case phrases > 0:
		state = fmt.Sprintf("Found a likely recovery phrase in %s", several(phrases, "file", "files"))
		if others > 0 {
			state += fmt.Sprintf(", and recovery words in %s more", thousands(others))
		}
	case others > 0:
		state = fmt.Sprintf("Found recovery words in %s", several(others, "file", "files"))
	}
	if p.Stopped {
		state += " (stopped before the end)"
	}
	good := model.Say(phrases+others == 0)
	if p.Stopped || p.Full {
		good = model.NotKnown
	}
	var more []Line
	if len(p.Folders) > 0 {
		more = append(more, Line{Heading, "What was searched"})
		for _, folder := range p.Folders {
			more = append(more, Line{Command, folder})
		}
	}
	more = append(more, Line{Text, several(p.Read, "file", "files") + " read. Text files, Word and LibreOffice documents, rich text and settings files count; pictures, PDFs and program code do not, and neither do folders of program code such as node_modules."})
	var unread []string
	if p.Cloud > 0 {
		unread = append(unread, fmt.Sprintf("%s kept only in the cloud, as reading them would download them", several(p.Cloud, "file", "files")))
	}
	if p.Big > 0 {
		unread = append(unread, fmt.Sprintf("%s larger than %d MB", several(p.Big, "file", "files"), phrase.Most>>20))
	}
	if p.Locked > 0 {
		unread = append(unread, fmt.Sprintf("%s that could not be opened", several(p.Locked, "file or folder", "files or folders")))
	}
	if len(unread) > 0 {
		more = append(more, Line{Text, "Not read: " + strings.Join(unread, "; ") + "."})
	}
	if p.Full {
		more = append(more, Line{Text, fmt.Sprintf("The search stops after %s files, and stopped there, so some files were not read.", thousands(phrase.Limit))})
	}
	if p.Stopped {
		more = append(more, Line{Text, "The search was stopped before it was done, so some files were not read."})
	}
	more = append(more, Line{Aside, "A phrase can also hide where this search does not look: in a photo or screenshot, a PDF, a password manager, an email, a note-taking app's own storage, or written in another language's word list."})
	row := b.topic("Recovery phrases in files", state, good, about, "phrases", more...)
	if phrases > 0 {
		// The finding is about the files, so the row takes their level here.
		row.Level, row.Cells[0] = First, First.String()
	} else if others > 0 {
		row.Level, row.Cells[0] = Look, Look.String()
	}
	return row
}

// thousands writes a number with commas, as 12,480.
func thousands(n int) string {
	text := strconv.Itoa(n)
	for i := len(text) - 3; i > 0; i -= 3 {
		text = text[:i] + "," + text[i:]
	}
	return text
}

// several writes a number with the right form of a word, and commas in
// a large number, as "1 file" or "12,480 files".
func several(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return thousands(n) + " " + many
}
