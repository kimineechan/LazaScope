//go:build windows

// The browsers' record files hold Windows paths, and this package joins and
// judges them the way Windows does, so its tests run on Windows only.

package browsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazascope/internal/model"
)

// A settings file as a Chromium browser writes it, cut down to what is read.
const chromiumFile = `{"extensions":{"settings":{
 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"location":1,"from_webstore":true,"disable_reasons":[],"path":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\1.2_0",
   "manifest":{"name":"Ad Blocker","version":"1.2","description":"Blocks adverts.","update_url":"https://clients2.google.com/service/update2/crx"},
   "active_permissions":{"api":["storage","tabs","webRequest","webRequestBlocking"],"explicit_host":["<all_urls>"],"scriptable_host":[]}},
 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"location":4,"disable_reasons":[],"path":"C:\\Users\\sam\\dev\\my-extension",
   "manifest":{"name":"My Extension","version":"0.1"},"active_permissions":{"api":["storage"],"explicit_host":["https://example.com/*"]}},
 "cccccccccccccccccccccccccccccccc":{"location":3,"disable_reasons":[],"path":"cccccccccccccccccccccccccccccccc\\9.0_0",
   "manifest":{"name":"Shopping Helper","version":"9.0"},"active_permissions":{"api":["cookies","history",{"socket":["tcp-connect"]}],"scriptable_host":["*://*/*"]}},
 "dddddddddddddddddddddddddddddddd":{"location":7,"disable_reasons":[],"manifest":{"name":"Work Filter","version":"2"}},
 "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":{"location":1,"from_webstore":true,"disable_reasons":[1],"manifest":{"name":"Switched Off","version":"1"}},
 "ffffffffffffffffffffffffffffffff":{"location":1,"state":0,"from_webstore":true,"manifest":{"name":"Old Style Off","version":"1"}},
 "gggggggggggggggggggggggggggggggg":{"location":5,"manifest":{"name":"PDF Viewer","version":"1"}},
 "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh":{"location":10,"manifest":{"name":"Store Payments","version":"1"}},
 "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii":{"disable_reasons":[8192]},
 "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj":{"location":6,"was_installed_by_default":true,"from_webstore":true,"manifest":{"name":"Docs Offline","version":"1"}},
 "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk":{"location":1,"from_webstore":false,"manifest":{"name":"From A File","version":"1","update_url":"https://example.com/updates.xml"}},
 "llllllllllllllllllllllllllllllll":{"location":8,"manifest":{"name":"By Shortcut","version":"1"}},
 "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm":{"location":1,"manifest":{"name":"From Edge Store","version":"1","update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx"}},
 "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn":{"location":1,"from_webstore":true,"state":1,"manifest":{"name":"__MSG_appName__","version":"1","default_locale":"en"}}
}}}`

func byName(t *testing.T, list []model.Extension, name string) model.Extension {
	t.Helper()
	for _, e := range list {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no extension named %q among %d", name, len(list))
	return model.Extension{}
}

func TestChromium(t *testing.T) {
	list, err := Chromium([]byte(chromiumFile), "Google Chrome", "Profile 1", `C:\Users\sam\AppData\Local\Google\Chrome\User Data\Profile 1`)
	if err != nil {
		t.Fatal(err)
	}
	// Parts of the browser and notes about extensions that are not there are left out.
	if len(list) != 11 {
		t.Fatalf("%d extensions, want 11", len(list))
	}
	blocker := byName(t, list, "Ad Blocker")
	if blocker.Source != model.FromStore || !blocker.Enabled || !blocker.EverySite || blocker.Version != "1.2" || blocker.Browser != "Google Chrome" || blocker.Profile != "Profile 1" || blocker.About != "Blocks adverts." {
		t.Errorf("the ad blocker: %+v", blocker)
	}
	if blocker.Folder != `C:\Users\sam\AppData\Local\Google\Chrome\User Data\Profile 1\Extensions\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\1.2_0` {
		t.Errorf("its folder: %s", blocker.Folder)
	}
	if strings.Join(blocker.May, "|") != "watch web traffic as it passes|see the addresses of the pages you have open" {
		t.Errorf("its rights: %q", blocker.May)
	}
	mine := byName(t, list, "My Extension")
	if mine.Source != model.Unpacked || mine.EverySite || mine.Folder != `C:\Users\sam\dev\my-extension` || len(mine.May) != 0 {
		t.Errorf("the developer's own: %+v", mine)
	}
	helper := byName(t, list, "Shopping Helper")
	if helper.Source != model.FromOutside || !helper.EverySite || strings.Join(helper.May, "|") != "read the cookies that keep you signed in|read your browsing history" {
		t.Errorf("the one another program added: %+v", helper)
	}
	for name, source := range map[string]model.ExtensionSource{
		"Work Filter": model.ByPolicy, "Docs Offline": model.WithBrowser, "From A File": model.FromFile, "By Shortcut": model.CommandLine, "From Edge Store": model.FromStore,
	} {
		if got := byName(t, list, name).Source; got != source {
			t.Errorf("%s: came from %q, want %q", name, got, source)
		}
	}
	for _, name := range []string{"Switched Off", "Old Style Off"} {
		if byName(t, list, name).Enabled {
			t.Errorf("%s is shown as switched on", name)
		}
	}
	// A name kept in the extension's own list of words cannot be looked up
	// when its folder is not there: its number stands in.
	if e := byName(t, list, "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"); e.Source != model.FromStore || !e.Enabled {
		t.Errorf("the extension with a name to look up: %+v", e)
	}

	for _, broken := range []string{"", "not json", `{"extensions":{"settings":"no"}}`} {
		if _, err := Chromium([]byte(broken), "Google Chrome", "Default", ""); err == nil && broken != "" {
			t.Errorf("%q was read without complaint", broken)
		}
	}
	if list, err := Chromium([]byte(`{}`), "Google Chrome", "Default", ""); err != nil || len(list) != 0 {
		t.Errorf("a file with no extensions: %v, %v", list, err)
	}
}

const firefoxFile = `{"schemaVersion":37,"addons":[
 {"id":"uBlock0@raymondhill.net","type":"extension","version":"1.62.0","location":"app-profile","active":true,"signedState":2,"path":"C:\\x\\uBlock0@raymondhill.net.xpi",
  "defaultLocale":{"name":"uBlock Origin","description":"An efficient blocker."},"installTelemetryInfo":{"source":"amo"},
  "userPermissions":{"permissions":["storage","tabs","webRequest"],"origins":["<all_urls>"]}},
 {"id":"mine@example.com","type":"extension","version":"0.1","location":"app-profile","active":true,"signedState":0,"defaultLocale":{"name":"Home Made"},"installTelemetryInfo":{"source":"file"}},
 {"id":"signed-file@example.com","type":"extension","version":"1","location":"app-profile","active":true,"signedState":2,"defaultLocale":{"name":"Signed File"},"installTelemetryInfo":{"source":"file"}},
 {"id":"side@example.com","type":"extension","version":"1","location":"winreg-app-user","active":true,"signedState":2,"defaultLocale":{"name":"Side Loaded"}},
 {"id":"work@example.com","type":"extension","version":"1","location":"app-profile","active":true,"signedState":2,"defaultLocale":{"name":"Work Filter"},"installTelemetryInfo":{"source":"enterprise-policy"}},
 {"id":"off@example.com","type":"extension","version":"1","location":"app-profile","active":false,"userDisabled":true,"signedState":2,"defaultLocale":{"name":"Switched Off"},"installTelemetryInfo":{"source":"sync"}},
 {"id":"nameless@example.com","type":"extension","version":"1","location":"app-profile","active":true,"signedState":2},
 {"id":"theme@example.com","type":"theme","version":"1","location":"app-profile","active":true,"signedState":2,"defaultLocale":{"name":"A Theme"}},
 {"id":"formautofill@mozilla.org","type":"extension","version":"1","location":"app-builtin-addons","active":true,"defaultLocale":{"name":"Form Autofill"}},
 {"id":"system@mozilla.org","type":"extension","version":"1","location":"app-system-defaults","active":true,"defaultLocale":{"name":"System"}}
]}`

func TestFirefox(t *testing.T) {
	list, err := Firefox([]byte(firefoxFile), "abc.default-release")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 7 {
		t.Fatalf("%d extensions, want 7: themes and what comes with Firefox are left out", len(list))
	}
	blocker := byName(t, list, "uBlock Origin")
	if blocker.Source != model.FromStore || !blocker.Enabled || !blocker.EverySite || blocker.Browser != "Firefox" || blocker.Profile != "abc.default-release" || len(blocker.May) != 2 {
		t.Errorf("the ad blocker: %+v", blocker)
	}
	for name, source := range map[string]model.ExtensionSource{
		"Home Made": model.FromFile, "Signed File": model.FromFile, "Side Loaded": model.FromOutside, "Work Filter": model.ByPolicy, "Switched Off": model.FromStore, "nameless@example.com": model.FromStore,
	} {
		if got := byName(t, list, name).Source; got != source {
			t.Errorf("%s: came from %q, want %q", name, got, source)
		}
	}
	if byName(t, list, "Switched Off").Enabled {
		t.Error("an extension that is off is shown as on")
	}
	if _, err := Firefox([]byte("not json"), "x"); err == nil {
		t.Error("a broken record was read without complaint")
	}
}

func TestRights(t *testing.T) {
	everySite, may := Rights([]string{"storage", "debugger", "nativeMessaging", "webRequest", "webRequestBlocking", "TABS"}, []string{"https://example.com/*"})
	if everySite || strings.Join(may, "|") != "take full control of pages|talk to a program on this PC|watch web traffic as it passes|see the addresses of the pages you have open" {
		t.Errorf("got %v, %q", everySite, may)
	}
	for _, pattern := range []string{"<all_urls>", "*://*/*", "https://*/*", " http://*/* "} {
		if everySite, _ := Rights(nil, []string{pattern}); !everySite {
			t.Errorf("%q was not read as every site", pattern)
		}
	}
	// An older extension writes its sites among its rights.
	if everySite, _ := Rights([]string{"tabs", "<all_urls>"}, nil); !everySite {
		t.Error("a site pattern among the rights was missed")
	}
	if everySite, may := Rights(nil, nil); everySite || may != nil {
		t.Errorf("no rights gave %v, %q", everySite, may)
	}
	for _, right := range rights {
		if right.says == "" || strings.HasSuffix(right.says, ".") {
			t.Errorf("the right %s is worded %q", right.name, right.says)
		}
	}
}

// The whole of it, on folders made up to look like a PC's.
func TestList(t *testing.T) {
	local, roaming := t.TempDir(), t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	chrome := filepath.Join(local, `Google\Chrome\User Data`)
	write(filepath.Join(chrome, "Default", "Secure Preferences"), chromiumFile)
	// The older file names the same extensions again, and one more.
	write(filepath.Join(chrome, "Default", "Preferences"), `{"extensions":{"settings":{
	 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"location":1,"from_webstore":true,"manifest":{"name":"Ad Blocker","version":"1.2"}},
	 "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz":{"location":1,"from_webstore":true,"manifest":{"name":"Only In The Old File","version":"1"}}}}}`)
	// The name of this one is in its own list of words, on disk.
	write(filepath.Join(chrome, "Default", "Extensions", "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn", "1_0", "_locales", "en", "messages.json"), `{"appname":{"message":"Named In Its Folder"}}`)
	write(filepath.Join(chrome, "Default", "Secure Preferences"), strings.Replace(chromiumFile, `"manifest":{"name":"__MSG_appName__","version":"1","default_locale":"en"}`,
		`"path":"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn\\1_0","manifest":{"name":"__MSG_appName__","version":"1","default_locale":"en"}`, 1))
	write(filepath.Join(chrome, "Profile 2", "Secure Preferences"), `{"extensions":{"settings":{}}}`)
	write(filepath.Join(chrome, "Broken", "Preferences"), `{{{`)
	write(filepath.Join(chrome, "Crashpad", "settings.dat"), `not a profile`)
	write(filepath.Join(roaming, `Mozilla\Firefox\Profiles\abc.default-release\extensions.json`), firefoxFile)
	write(filepath.Join(roaming, `Mozilla\Firefox\Profiles\never-used\times.json`), `{}`)
	write(filepath.Join(roaming, `Mozilla\Firefox\Profiles\broken\extensions.json`), `[[[`)

	list, unread := List(Folders{Local: local, Roaming: roaming})
	if len(list) != 12+7 {
		t.Errorf("%d extensions, want 19", len(list))
	}
	if e := byName(t, list, "Named In Its Folder"); e.ID != "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" {
		t.Errorf("the name looked up on disk: %+v", e)
	}
	byName(t, list, "Only In The Old File")
	count := 0
	for _, e := range list {
		if e.Name == "Ad Blocker" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("an extension named in both files is listed %d times", count)
	}
	if len(unread) != 2 || !strings.Contains(strings.Join(unread, " "), "Google Chrome (profile Broken)") || !strings.Contains(strings.Join(unread, " "), "Firefox (profile broken)") {
		t.Errorf("the notes of what could not be read: %q", unread)
	}
	// A PC with no browsers of these kinds gives nothing and no complaint.
	if list, unread := List(Folders{Local: t.TempDir(), Roaming: t.TempDir()}); len(list) != 0 || len(unread) != 0 {
		t.Errorf("empty folders gave %v, %v", list, unread)
	}
}
