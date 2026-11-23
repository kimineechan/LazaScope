package rules

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

// extension is a browser extension as a start-up entry.
func extension(name string, source model.ExtensionSource, do ...func(x *model.Extension)) model.Startup {
	x := &model.Extension{Browser: "Google Chrome", Profile: "Default", ID: "abcdefghijklmnopabcdefghijklmnop", Name: name, Version: "1.0", Enabled: true, Source: source}
	for _, change := range do {
		change(x)
	}
	return model.Startup{Kind: model.BrowserExtension, Name: name, Where: "Google Chrome, profile Default", Enabled: x.Enabled, Trigger: "Whenever Google Chrome is open", Extension: x}
}

func everySite(x *model.Extension) {
	x.EverySite, x.May = true, []string{"read the cookies that keep you signed in"}
}
func switchedOff(x *model.Extension) { x.Enabled = false }

func init() {
	changes = append(changes, []change{
		// Browser extensions.
		{"an ad blocker from the store that may read every site", add(extension("Ad Blocker", model.FromStore, everySite)), ""},
		{"an extension the browser's maker ships with it", add(extension("Docs Offline", model.WithBrowser)), ""},
		{"an extension added by hand from a file", add(extension("From A File", model.FromFile)), "extension-not-from-store:medium"},
		{"a developer's own extension, loaded from a folder", add(extension("My Extension", model.Unpacked)), "extension-not-from-store:medium"},
		{"an extension another program put into the browser", add(extension("Shopping Helper", model.FromOutside, everySite)), "extension-not-from-store:medium"},
		{"an extension loaded by a switch on the browser's shortcut", add(extension("By Shortcut", model.CommandLine)), "extension-not-from-store:high"},
		{"an extension whose origin the browser does not record", add(extension("Mystery", model.SourceUnknown)), "extension-not-from-store:medium"},
		{"the same, switched off in the browser", add(extension("Shopping Helper", model.FromOutside, switchedOff)), ""},
		{"an extension forced on by a policy", add(extension("Work Filter", model.ByPolicy)), "extension-forced:medium"},
		{"a forced extension that is switched off", add(extension("Work Filter", model.ByPolicy, switchedOff)), ""},
	}...)
}

func TestExtensionWording(t *testing.T) {
	s := healthy()
	s.Startup = append(s.Startup, extension("Shopping Helper", model.FromOutside, everySite, func(x *model.Extension) {
		x.Browser, x.Profile, x.Folder = "Microsoft Edge", "Profile 2", `C:\Users\sam\AppData\Local\Microsoft\Edge\User Data\Profile 2\Extensions\abc\1_0`
	}))
	f := Check(s)[0]
	for _, want := range []string{
		"Shopping Helper is switched on in Microsoft Edge (profile Profile 2).",
		"Another program on this PC put it into the browser.",
		"It may read and change the pages of every website you visit and read the cookies that keep you signed in.",
	} {
		if !strings.Contains(f.Reason, want) {
			t.Errorf("the reason lacks %q:\n%s", want, f.Reason)
		}
	}
	if !strings.Contains(f.Advice, "open Microsoft Edge, open its menu and choose Extensions") {
		t.Errorf("the advice does not say where to switch it off: %s", f.Advice)
	}
	got := map[string]string{}
	for _, fact := range f.Facts {
		got[fact.Label] = fact.Value
	}
	if got["Extension"] != "Shopping Helper" || got["Browser"] != "Microsoft Edge, profile Profile 2" || got["Where it came from"] != "Added by another program" ||
		got["What it may do"] != "Read and change the pages of every website you visit and read the cookies that keep you signed in" || got["Folder"] == "" || got["File"] != "" {
		t.Errorf("the facts: %+v", f.Facts)
	}
	// An extension has no program file, and the rules about files leave it alone.
	for _, finding := range Check(s) {
		if finding.Rule != "extension-not-from-store" {
			t.Errorf("an extension set off %s", finding.Rule)
		}
	}
}
