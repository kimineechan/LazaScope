package view

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

// A browser extension has its own row among what starts by itself: which
// browser, where it came from and what it may do. It is counted apart from
// what starts with Windows.
func TestExtensionRows(t *testing.T) {
	s := pc()
	s.Startup = append(s.Startup,
		model.Startup{Kind: model.BrowserExtension, Name: "Ad Blocker", Where: "Firefox, profile abc", Enabled: true, Description: "Blocks adverts.",
			Extension: &model.Extension{Browser: "Firefox", Profile: "abc", ID: "blocker@example.com", Name: "Ad Blocker", Version: "1.2", About: "Blocks adverts.", Enabled: true,
				Source: model.FromStore, EverySite: true, May: []string{"watch web traffic as it passes"}, Folder: `C:\Users\sam\AppData\Roaming\Mozilla\Firefox\Profiles\abc\extensions\blocker.xpi`}},
		model.Startup{Kind: model.BrowserExtension, Name: "Shopping Helper", Where: "Microsoft Edge, profile Default", Enabled: true,
			Extension: &model.Extension{Browser: "Microsoft Edge", Profile: "Default", ID: "abcdefghijklmnop", Name: "Shopping Helper", Enabled: true, Source: model.FromOutside}},
		model.Startup{Kind: model.BrowserExtension, Name: "Old One", Where: "Google Chrome, profile Default",
			Extension: &model.Extension{Browser: "Google Chrome", Profile: "Default", ID: "ponmlkjihgfedcba", Name: "Old One", Source: model.FromStore}})
	book := build(s)
	page := book.Startup

	row := find(t, page, "Ad Blocker")
	if got := strings.Join(row.Cells, " | "); got != ` | Ad Blocker | Firefox extension | From the browser's store | C:\Users\sam\AppData\Roaming\Mozilla\Firefox\Profiles\abc\extensions\blocker.xpi` {
		t.Errorf("the row: %s", got)
	}
	if row.Group != "extension" || row.Windows || row.Path == "" {
		t.Errorf("the row is grouped %q, part of Windows %v, path %q", row.Group, row.Windows, row.Path)
	}
	said := words(row.Detail)
	for _, want := range []string{
		"A small program added to a web browser.", "Browser: Firefox, profile abc", "Where it came from: From the browser's store", "Version: 1.2", "What it says it is for: Blocks adverts.",
		"It may read and change the pages of every website you visit.", "It may also: watch web traffic as it passes", "Its number in the browser: blocker@example.com",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the detail lacks %q:\n%s", want, said)
		}
	}
	if strings.Contains(said, "could not work out which file") || strings.Contains(said, "signature") {
		t.Errorf("an extension is spoken of as a program file:\n%s", said)
	}

	flagged := find(t, page, "Shopping Helper")
	if flagged.Level != Look || flagged.Cells[3] != "Added by another program" || !strings.Contains(words(flagged.Detail), "It is not allowed to read every website") {
		t.Errorf("the flagged extension: %v\n%s", flagged.Cells, words(flagged.Detail))
	}
	off := find(t, page, "Old One")
	if !off.Off || off.Cells[0] != "Off" || !strings.Contains(words(off.Detail), "switched off in the browser") {
		t.Errorf("the extension that is off: %v", off.Cells)
	}

	// The overview counts what starts with Windows, and the extensions apart.
	if got := book.Glances[model.StartsWithWindows].Facts; got != "3 things are set to start by themselves. 1 is not part of Windows. 3 browser extensions." {
		t.Errorf("the overview says %q", got)
	}
}
