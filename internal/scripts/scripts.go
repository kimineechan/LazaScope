// Package scripts reads a script file as what it is, a text file of
// commands, and says in plain words what those commands do.
//
// It is a reading, not a test: nothing is run. It looks for the words a
// script uses to reach the internet, to change what starts with Windows, to
// touch the antivirus and the like. A script can hide what it does, and a
// harmless script can do every one of these things, so what is found here
// is a fact about the text and never a verdict.
//
// The package calls nothing and knows nothing about Windows or windows, so
// that another program can use it on its own files.
package scripts

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The endings of files that a scripting tool runs as text.
var endings = map[string]bool{}

func init() {
	for _, ending := range strings.Fields(`
		.bat .cmd .vbs .vbe .js .jse .wsf .wsh .ps1 .hta
		.py .pyw .mjs .cjs .ahk .au3`) {
		endings[ending] = true
	}
}

// ending returns the ending of a file's name in small letters, with its dot.
func ending(path string) string {
	name := path
	if cut := strings.LastIndexAny(name, `\/`); cut >= 0 {
		name = name[cut+1:]
	}
	if dot := strings.LastIndexByte(name, '.'); dot > 0 {
		return strings.ToLower(name[dot:])
	}
	return ""
}

// Is reports whether a file is a script, going by its name.
func Is(path string) bool { return endings[ending(path)] }

// Encoded reports whether a file is a script saved in a scrambled form that
// cannot be read as text, going by its name.
func Encoded(path string) bool {
	end := ending(path)
	return end == ".vbe" || end == ".jse"
}

// Limit is the largest file that is read. A script longer than this was
// not written by hand.
const Limit = 2 << 20

// Reading is what a script's text shows.
type Reading struct {
	Lines []string // how it begins: its first lines that are not empty
	More  bool     // it goes on after those lines
	Signs []string // what it does, each as a sentence
}

// A sign is one thing a script can be seen to do, and the words that
// give it away. The words are matched in small letters.
type sign struct {
	says  string
	words []string
}

// The signs, the weightiest first.
var signs = []sign{
	{"It changes Microsoft Defender's settings.", []string{"set-mppreference", "add-mppreference", "disableantispyware", "disablerealtimemonitoring", `windows defender\exclusions`, "windows defender/exclusions"}},
	{"It removes the backup copies of files that Windows keeps.", []string{"vssadmin delete", "vssadmin.exe delete", "shadowcopy delete", "wbadmin delete", "resize shadowstorage"}},
	{"It clears Windows' logs.", []string{"wevtutil cl", "wevtutil.exe cl", "wevtutil clear-log", "clear-eventlog"}},
	{"It changes the firewall.", []string{"netsh advfirewall", "netsh firewall", "new-netfirewallrule", "set-netfirewallprofile", "set-netfirewallrule", "remove-netfirewallrule"}},
	{"It adds or changes user accounts.", []string{"net user ", "net.exe user ", "net1 user ", "new-localuser", "net localgroup", "add-localgroupmember", "set-localuser"}},
	{"It fetches something from the internet.", []string{"invoke-webrequest", "invoke-restmethod", "iwr ", "irm ", "downloadstring", "downloadfile", "downloaddata", "net.webclient", "start-bitstransfer", "bitsadmin",
		"curl ", "curl.exe", "wget ", "-urlcache", "msxml2.xmlhttp", "msxml2.serverxmlhttp", "winhttp.winhttprequest", "urllib.request", "requests.get", "requests.post", "fetch(", "https.get(", "http.get(", "https.request(", "xmlhttprequest"}},
	{"It runs a piece of text as commands, so what it does can change without the file changing.", []string{"invoke-expression", "iex ", "iex(", "|iex", "| iex", "eval(", "executeglobal", "new function(", "exec(compile", "invoke-command -scriptblock ([scriptblock]::create"}},
	{"It unpacks text that is stored in an encoded form.", []string{"frombase64string", "atob(", "b64decode", "-encodedcommand", " -enc ", "certutil -decode", "certutil.exe -decode", "[convert]::frombase64"}},
	{"It changes what starts with Windows.", []string{"schtasks /create", "schtasks.exe /create", "register-scheduledtask", "new-scheduledtask", `currentversion\run`, "currentversion/run", "sc create", "sc.exe create", "new-service",
		`start menu\programs\startup`, "userinit", "image file execution options"}},
	{"It stops or switches off services.", []string{"stop-service", "sc stop", "sc.exe stop", "net stop", "start= disabled", "-startuptype disabled", "start=disabled"}},
	{"It removes apps or parts of Windows.", []string{"remove-appxpackage", "remove-appxprovisionedpackage", "remove-windowscapability", "disable-windowsoptionalfeature", "/disable-feature", "/remove-package", "uninstall-package", "winget uninstall", "msiexec /x", "msiexec.exe /x"}},
	{"It changes settings in the registry, Windows' settings database.", []string{"reg add", "reg.exe add", "reg delete", "reg.exe delete", "reg import", "set-itemproperty", "new-itemproperty", "remove-itemproperty", "regwrite", "regdelete", "winreg.setvalue"}},
	{"It deletes files or folders.", []string{"remove-item", "del /", "del \"", "erase /", "rd /s", "rmdir /s", "fs.unlink", "fs.rm(", "fs.rmsync", "fs.rmdir", "os.remove(", "os.unlink(", "shutil.rmtree", "deletefile", "deletefolder", "ri -r"}},
	{"It asks PowerShell to work without showing a window.", []string{"-windowstyle hidden", "-w hidden", "-window hidden", "-win hidden", "-windowstyle h ", "-noni -w h"}},
}

// Read reads a script's text. most is how many of its first lines to keep.
func Read(text string, most int) Reading {
	var r Reading
	// What breaks words up to hide them is taken out before looking.
	plain := strings.NewReplacer("^", "", "`", "", "\r", "", "\t", " ").Replace(strings.ToLower(text))
	plain = strings.Join(strings.Fields(plain), " ")
	for _, sign := range signs {
		for _, word := range sign.words {
			if strings.Contains(plain, word) {
				r.Signs = append(r.Signs, sign.says)
				break
			}
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(strings.ReplaceAll(line, "\t", "    "), " \r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(r.Lines) == most {
			r.More = true
			break
		}
		r.Lines = append(r.Lines, shorten(printable(line), 150))
	}
	return r
}

// printable swaps the characters that would not show for a dot.
func printable(line string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7F || r == utf8.RuneError {
			return '.'
		}
		return r
	}, line)
}

// shorten cuts a line that is too long to show, and says so with dots.
func shorten(line string, most int) string {
	runes := []rune(line)
	if len(runes) <= most {
		return line
	}
	return string(runes[:most-3]) + "..."
}

// Text turns the bytes of a script file into text. Scripts are saved in
// several ways: plain, with a mark at the start that says which way, or
// two bytes to a letter as Windows' own tools often write them.
func Text(data []byte) (text string, readable bool) {
	switch {
	case len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF:
		data = data[3:]
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		return wide(data[2:], false), true
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		return wide(data[2:], true), true
	case len(data) >= 8 && data[1] == 0 && data[3] == 0 && data[5] == 0 && data[7] == 0:
		return wide(data, false), true // two bytes to a letter, with no mark
	}
	// A file with empty bytes in it is not text, whatever its name says.
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	for _, b := range sample {
		if b == 0 {
			return "", false
		}
	}
	return string(data), true
}

func wide(data []byte, bigEnd bool) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		if bigEnd {
			units[i] = uint16(data[2*i])<<8 | uint16(data[2*i+1])
		} else {
			units[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
		}
	}
	return string(utf16.Decode(units))
}
