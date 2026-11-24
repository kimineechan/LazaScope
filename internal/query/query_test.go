package query

import (
	"strings"
	"testing"
)

var rows = map[string]Record{
	"anydesk": {Fields: map[string][]string{"name": {"AnyDesk Service"}, "kind": {"Service"}, "path": {`C:\Program Files (x86)\AnyDesk\AnyDesk.exe`},
		"signed": {"yes"}, "maker": {"AnyDesk Software GmbH"}, "level": {"look"}, "windows": {"no"}, "vt": {"clean"}, "rule": {"remote-tool"}, "attack": {"T1219"}},
		Text: "Worth a look | AnyDesk Service | Service | AnyDesk Software GmbH | remote control"},
	"impostor": {Fields: map[string][]string{"name": {"Windows Host Service"}, "kind": {"Registry Run"}, "path": {`C:\Users\sam\AppData\Roaming\svchost.exe`},
		"signed": {"no"}, "level": {"first"}, "windows": {"no"}, "vt": {"flagged"}, "rule": {"startup-unsigned", "startup-system-name"}, "attack": {"T1036.005", "T1547.001"}},
		Text: "Look first | Windows Host Service | Registry Run | Not signed"},
	"audio": {Fields: map[string][]string{"name": {"Audiosrv"}, "kind": {"Service"}, "path": {`C:\Windows\System32\audiosrv.dll`}, "signed": {"yes"}, "level": {"none"}, "windows": {"yes"}, "vt": {"notasked"}},
		Text: "Audiosrv | Service | Microsoft Windows"},
	"driver": {Fields: map[string][]string{"name": {"thing"}, "kind": {"Driver"}, "path": {`C:\Windows\System32\drivers\thing.sys`}, "signed": {"broken"}, "level": {"first"}, "windows": {"no"}, "pid": {"4"}},
		Text: "thing | Driver"},
	"tool": {Fields: map[string][]string{"name": {"tool.exe"}, "path": {`C:\Program Files\Tool, Ltd\tool.exe`}, "pid": {"1234"}, "port": {"443", "50112"}},
		Text: "tool.exe | Program Files"},
}

func found(t *testing.T, search string) string {
	t.Helper()
	q, err := Parse(search)
	if err != nil {
		t.Fatalf("%q: %v", search, err)
	}
	var names []string
	for _, name := range []string{"anydesk", "impostor", "audio", "driver", "tool"} {
		if q.Match(rows[name]) {
			names = append(names, name)
		}
	}
	return strings.Join(names, " ")
}

func TestSearches(t *testing.T) {
	for search, want := range map[string]string{
		"":                              "anydesk impostor audio driver tool",
		"   ":                           "anydesk impostor audio driver tool",
		"anydesk":                       "anydesk",
		"ANYDESK":                       "anydesk",
		"*anydesk*":                     "anydesk",
		"kind:service":                  "anydesk audio",
		"Kind:SERVICE":                  "anydesk audio",
		"kind:service,driver":           "anydesk audio driver",
		"kind:service -windows:yes":     "anydesk",
		"signed:no":                     "impostor",
		"signed:broken":                 "driver",
		"-signed:yes":                   "impostor driver tool",
		`path:*\Users\*`:                "impostor",
		`path:*.sys`:                    "driver",
		`path:c:\windows\*`:             "audio driver",
		`path:system32`:                 "audio driver",
		`path:"Tool, Ltd"`:              "tool",
		`"program files"`:               "tool",
		"pid:4":                         "driver",
		"pid:12*":                       "tool",
		"port:443":                      "tool",
		"port:44":                       "",
		"level:first":                   "impostor driver",
		"level:first,look":              "anydesk impostor driver",
		"rule:system-name":              "impostor",
		"attack:T1547":                  "impostor",
		"attack:t1219":                  "anydesk",
		"vt:flagged":                    "impostor",
		"vt:notasked":                   "audio",
		`C:\Users`:                      "",
		"windows:no level:first signed": "impostor", // the word "signed" is in "Not signed"
	} {
		if got := found(t, search); got != want {
			t.Errorf("%q found %q, want %q", search, got, want)
		}
	}
}

func TestBadSearches(t *testing.T) {
	for search, want := range map[string]string{
		"knd:service":         "there is no field called knd",
		"signed:maybe":        "signed takes yes, no or broken, not maybe",
		"level:":              "say what level should be",
		`name:"open`:          "a quote was opened and not closed",
		"windows:yes vt:lots": "vt takes flagged, clean, unknown or notasked, not lots",
	} {
		_, err := Parse(search)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q gave %v, want %q", search, err, want)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pattern, text string
		want          bool
	}{
		{"*", "", true}, {"*", "anything", true}, {"a*c", "abbbc", true}, {"a*c", "abbb", false},
		{"a?c", "abc", true}, {"a?c", "ac", false}, {`c:\*\x.exe`, `c:\a\b\x.exe`, true}, {"*.exe", "x.exe.bak", false},
		{"**a", "bba", true}, {"a*b*c", "axxbyyc", true}, {"a*b*c", "axxcyyb", false},
	} {
		if got := glob(c.pattern, c.text); got != c.want {
			t.Errorf("glob(%q, %q) = %v", c.pattern, c.text, got)
		}
	}
}

func TestHelp(t *testing.T) {
	help := strings.Join(Help(), "\n")
	for _, f := range Fields {
		if !strings.Contains(help, f.Name+": ") {
			t.Errorf("the help does not explain %s", f.Name)
		}
	}
}
