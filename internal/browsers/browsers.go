// Package browsers lists the extensions added to the web browsers on a PC.
//
// An extension is a small program that lives inside the browser. It loads
// whenever the browser is open, and many are allowed to read and change
// every page the user visits, which makes them as much a part of "what
// starts by itself" as anything in the registry.
//
// The package reads the browsers' own records, which are plain files in
// the user's folders. It opens them for reading and starts no browser.
package browsers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"lazascope/internal/model"
)

// Folders says where the browsers keep their records for one account.
type Folders struct {
	Local   string // such as C:\Users\sam\AppData\Local
	Roaming string // such as C:\Users\sam\AppData\Roaming
}

// The browsers built on Chromium, and where each keeps its profiles.
var chromium = []struct{ name, folder, store string }{
	{"Google Chrome", `Google\Chrome\User Data`, "the Chrome Web Store"},
	{"Microsoft Edge", `Microsoft\Edge\User Data`, "the Chrome Web Store"},
	{"Brave", `BraveSoftware\Brave-Browser\User Data`, "the Chrome Web Store"},
	{"Vivaldi", `Vivaldi\User Data`, "the Chrome Web Store"},
	{"Opera", `Opera Software\Opera Stable`, "the Chrome Web Store"},
}

// most is the largest record file that is read. A real one is well under this.
const most = 64 << 20

// List returns the extensions of every browser found, and a note for each
// record that was there but could not be read.
func List(f Folders) (extensions []model.Extension, unread []string) {
	for _, browser := range chromium {
		// Opera keeps its records with the roaming settings, the rest with the local ones.
		root := filepath.Join(f.Local, browser.folder)
		if browser.name == "Opera" {
			root = filepath.Join(f.Roaming, browser.folder)
		}
		profiles, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		// Opera has one profile, which is the folder itself.
		folders := []string{}
		if _, err := os.Stat(filepath.Join(root, "Preferences")); err == nil {
			folders = append(folders, root)
		}
		for _, profile := range profiles {
			if profile.IsDir() {
				folders = append(folders, filepath.Join(root, profile.Name()))
			}
		}
		for _, folder := range folders {
			found, ok := chromiumProfile(browser.name, folder)
			if !ok {
				continue // not a profile: a folder of the browser's own
			}
			if found == nil {
				unread = append(unread, "The extensions of "+browser.name+" (profile "+filepath.Base(folder)+") could not be read.")
			}
			extensions = append(extensions, found...)
		}
	}
	profiles, _ := os.ReadDir(filepath.Join(f.Roaming, `Mozilla\Firefox\Profiles`))
	for _, profile := range profiles {
		path := filepath.Join(f.Roaming, `Mozilla\Firefox\Profiles`, profile.Name(), "extensions.json")
		data, err := read(path)
		if err != nil {
			continue // a profile that was never used has no record
		}
		found, err := Firefox(data, profile.Name())
		if err != nil {
			unread = append(unread, "The extensions of Firefox (profile "+profile.Name()+") could not be read.")
		}
		extensions = append(extensions, found...)
	}
	sort.SliceStable(extensions, func(i, j int) bool {
		a, b := extensions[i], extensions[j]
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return extensions, unread
}

func read(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > most {
		return nil, os.ErrInvalid
	}
	return os.ReadFile(path)
}

// chromiumProfile reads the extensions of one profile folder. ok is false
// when the folder is not a profile. A profile whose records cannot be read
// gives ok and nothing.
func chromiumProfile(browser, folder string) (found []model.Extension, ok bool) {
	// The browser keeps the list in one of two files, depending on its version.
	var lists [][]byte
	for _, name := range []string{"Secure Preferences", "Preferences"} {
		if data, err := read(filepath.Join(folder, name)); err == nil {
			lists = append(lists, data)
		}
	}
	if len(lists) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	readable := false
	for _, data := range lists {
		extensions, err := Chromium(data, browser, filepath.Base(folder), folder)
		if err != nil {
			continue
		}
		readable = true
		for _, extension := range extensions {
			if !seen[extension.ID] {
				seen[extension.ID] = true
				found = append(found, extension)
			}
		}
	}
	if !readable {
		return nil, true
	}
	if found == nil {
		found = []model.Extension{}
	}
	return found, true
}

// The places an extension can come from, as Chromium numbers them.
const (
	fromStore         = 1  // added by the user from the store
	fromOutside       = 2  // put there by another program, through a settings file
	fromRegistry      = 3  // put there by another program, through the registry
	unpacked          = 4  // loaded from a folder, with developer mode switched on
	component         = 5  // a part of the browser itself
	withBrowser       = 6  // offered by the browser's maker and fetched from the store
	policyFetched     = 7  // forced by a policy
	commandLine       = 8  // loaded by a switch on the line that starts the browser
	policy            = 9  // forced by a policy
	outsideComponent  = 10 // a part of the browser itself
	chromeStoreUpdate = "clients2.google.com/service/update2/crx"
	edgeStoreUpdate   = "edge.microsoft.com/extensionwebstorebase"
)

type chromiumRecord struct {
	Location       int             `json:"location"`
	State          *int            `json:"state"`
	DisableReasons json.RawMessage `json:"disable_reasons"`
	FromWebstore   bool            `json:"from_webstore"`
	ByDefault      bool            `json:"was_installed_by_default"`
	Path           string          `json:"path"`
	Manifest       *struct {
		Name          string `json:"name"`
		Version       string `json:"version"`
		Description   string `json:"description"`
		UpdateURL     string `json:"update_url"`
		DefaultLocale string `json:"default_locale"`
	} `json:"manifest"`
	Active struct {
		API        []json.RawMessage `json:"api"`
		Explicit   []string          `json:"explicit_host"`
		Scriptable []string          `json:"scriptable_host"`
	} `json:"active_permissions"`
}

// Chromium reads the extensions out of a Chromium browser's settings file.
// folder is the profile's folder, used to find an extension on disk.
func Chromium(data []byte, browser, profile, folder string) ([]model.Extension, error) {
	var file struct {
		Extensions struct {
			Settings map[string]chromiumRecord `json:"settings"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	var found []model.Extension
	for id, record := range file.Extensions.Settings {
		// Parts of the browser itself are not extensions anyone added, and a
		// record with no place of origin is a note the browser keeps about an
		// extension that is not installed.
		if record.Location == component || record.Location == outsideComponent || record.Location == 0 {
			continue
		}
		e := model.Extension{Browser: browser, Profile: profile, ID: id, Enabled: true}
		if record.State != nil && *record.State != 1 {
			e.Enabled = false
		}
		if reasons := strings.TrimSpace(string(record.DisableReasons)); reasons != "" && reasons != "[]" && reasons != "0" && reasons != "null" {
			e.Enabled = false
		}
		e.Folder = record.Path
		if e.Folder != "" && !filepath.IsAbs(e.Folder) {
			e.Folder = filepath.Join(folder, "Extensions", e.Folder)
		}
		update := ""
		if record.Manifest != nil {
			e.Name, e.Version, e.About, update = record.Manifest.Name, record.Manifest.Version, record.Manifest.Description, record.Manifest.UpdateURL
			if strings.HasPrefix(e.Name, "__MSG_") {
				e.Name = message(e.Folder, record.Manifest.DefaultLocale, e.Name)
			}
			if strings.HasPrefix(e.About, "__MSG_") {
				e.About = message(e.Folder, record.Manifest.DefaultLocale, e.About)
			}
		}
		if e.Name == "" || strings.HasPrefix(e.Name, "__MSG_") {
			e.Name = id
		}
		store := record.FromWebstore || strings.Contains(update, chromeStoreUpdate) || strings.Contains(update, edgeStoreUpdate)
		switch record.Location {
		case fromStore:
			e.Source = model.FromStore
			if !store {
				e.Source = model.FromFile // added by hand from a file, not through the store
			}
		case withBrowser:
			e.Source = model.WithBrowser
			if !record.ByDefault {
				e.Source = model.FromOutside
			}
		case fromOutside, fromRegistry:
			e.Source = model.FromOutside
		case unpacked:
			e.Source = model.Unpacked
		case policy, policyFetched:
			e.Source = model.ByPolicy
		case commandLine:
			e.Source = model.CommandLine
		default:
			e.Source = model.SourceUnknown
		}
		var api []string
		for _, raw := range record.Active.API {
			var name string
			if json.Unmarshal(raw, &name) == nil {
				api = append(api, name)
			}
		}
		e.EverySite, e.May = Rights(api, append(record.Active.Explicit, record.Active.Scriptable...))
		found = append(found, e)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	return found, nil
}

// message looks up a name that an extension keeps in a list of its own, one
// list per language. The name is written "__MSG_key__".
func message(folder, locale, name string) string {
	key := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
	if folder == "" || key == "" {
		return name
	}
	for _, language := range []string{locale, "en", "en_US", "en_GB"} {
		if language == "" {
			continue
		}
		data, err := read(filepath.Join(folder, "_locales", language, "messages.json"))
		if err != nil {
			continue
		}
		var messages map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &messages) != nil {
			continue
		}
		for have, entry := range messages {
			if strings.EqualFold(have, key) && strings.TrimSpace(entry.Message) != "" {
				return strings.TrimSpace(entry.Message)
			}
		}
	}
	return name
}

// The rights that matter most, in plain words. The key is the name the
// browser gives the right.
var rights = []struct{ name, says string }{
	{"debugger", "take full control of pages"},
	{"nativeMessaging", "talk to a program on this PC"},
	{"proxy", "change where web traffic is sent"},
	{"webRequest", "watch web traffic as it passes"},
	{"cookies", "read the cookies that keep you signed in"},
	{"history", "read your browsing history"},
	{"clipboardRead", "read what you copy"},
	{"management", "manage other extensions"},
	{"downloads", "start and manage downloads"},
	{"tabs", "see the addresses of the pages you have open"},
	{"privacy", "change the browser's privacy settings"},
	{"desktopCapture", "record the screen"},
	{"tabCapture", "record what a page shows"},
	{"geolocation", "ask where you are"},
}

// every lists the ways a site pattern is written when it means every site.
var every = map[string]bool{"<all_urls>": true, "*://*/*": true, "http://*/*": true, "https://*/*": true, "*://*/": true}

// Rights puts an extension's rights into plain words. everySite is true
// when it may read and change the pages of every website.
func Rights(api, sites []string) (everySite bool, may []string) {
	for _, site := range sites {
		if every[strings.TrimSpace(site)] {
			everySite = true
		}
	}
	for _, name := range api {
		if every[strings.TrimSpace(name)] {
			everySite = true
		}
	}
	for _, right := range rights {
		for _, name := range api {
			if strings.EqualFold(name, right.name) || (right.name == "webRequest" && strings.EqualFold(name, "webRequestBlocking")) {
				if len(may) == 0 || may[len(may)-1] != right.says {
					may = append(may, right.says)
				}
				break
			}
		}
	}
	return everySite, may
}

// Firefox reads the extensions out of a Firefox profile's record.
func Firefox(data []byte, profile string) ([]model.Extension, error) {
	var file struct {
		Addons []struct {
			ID            string `json:"id"`
			Type          string `json:"type"`
			Version       string `json:"version"`
			Location      string `json:"location"`
			Active        bool   `json:"active"`
			Path          string `json:"path"`
			SignedState   *int   `json:"signedState"`
			DefaultLocale struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"defaultLocale"`
			Install struct {
				Source string `json:"source"`
			} `json:"installTelemetryInfo"`
			Permissions struct {
				Permissions []string `json:"permissions"`
				Origins     []string `json:"origins"`
			} `json:"userPermissions"`
		} `json:"addons"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	var found []model.Extension
	for _, addon := range file.Addons {
		// Themes, dictionaries and language packs hold no code. What comes
		// with Firefox itself is not something anyone added.
		if addon.Type != "extension" || strings.HasPrefix(addon.Location, "app-builtin") || strings.HasPrefix(addon.Location, "app-system") {
			continue
		}
		e := model.Extension{Browser: "Firefox", Profile: profile, ID: addon.ID, Name: addon.DefaultLocale.Name, Version: addon.Version,
			About: addon.DefaultLocale.Description, Enabled: addon.Active, Folder: addon.Path}
		if e.Name == "" {
			e.Name = addon.ID
		}
		const signedByMozilla = 2
		signed := addon.SignedState != nil && *addon.SignedState >= signedByMozilla
		switch source := addon.Install.Source; {
		case source == "enterprise-policy":
			e.Source = model.ByPolicy
		case addon.Location != "app-profile" || source == "sideload" || source == "distribution":
			e.Source = model.FromOutside
		case addon.Location == "app-profile" && strings.HasPrefix(addon.Path, "temporary"), source == "temporary-addon":
			e.Source = model.Unpacked
		case !signed:
			e.Source = model.FromFile
		case source == "file":
			e.Source = model.FromFile
		default:
			e.Source = model.FromStore // Mozilla signs what its own site hands out
		}
		e.EverySite, e.May = Rights(addon.Permissions.Permissions, addon.Permissions.Origins)
		found = append(found, e)
	}
	return found, nil
}
