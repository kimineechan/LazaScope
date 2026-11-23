// Package cmdline follows a command to the file that does its work.
//
// A start-up entry stores a line of text such as
//
//	rundll32.exe "C:\Program Files\Thing\thing.dll",Start
//
// The program named first, rundll32, is part of Windows and tells nothing.
// The file that matters is the library it is handed. This package splits
// such a line into the program and what it is told, finds the program on
// disk, and for the go-betweens Windows comes with (rundll32, PowerShell,
// cmd and the like) picks out the file they are handed.
package cmdline

import (
	"regexp"
	"strings"

	"lazascope/internal/winpath"
)

// World answers what reading a command needs to know about a PC. The
// collectors give real answers and the tests give made-up ones.
type World struct {
	Expand  func(text string) string // put the values of names such as %SystemRoot% in
	IsFile  func(path string) bool   // there is a file, not a folder, at this path
	Windows string                   // the Windows folder, such as C:\Windows
	Search  []string                 // the folders a bare name such as "notepad" is looked for in, in order
	AppPath func(name string) string // where a bare name is registered to be found, or ""
}

// Carrier says what kind of go-between a program is.
type Carrier int

const (
	Direct  Carrier = iota // the program does its own work
	Library                // it runs a library it is handed: rundll32, regsvr32
	Script                 // it runs a script or commands it is handed: PowerShell, cmd, wscript, mshta
	Package                // it runs or installs a package it is handed: msiexec, java
)

// Command is a command taken apart.
type Command struct {
	Program   string // the program the command starts, with its full path when it was found
	Arguments string // what the program is told
	Found     bool   // the program is on disk
	Carrier   Carrier
	Target    string // the file a go-between is handed, or "" when none is named
	Inline    bool   // a script host given its instructions on the line itself, not in a file
}

// Works returns the file that does the work: what a go-between is handed,
// or else the program itself.
func (c Command) Works() string {
	if c.Target != "" {
		return c.Target
	}
	return c.Program
}

func (w World) expand(text string) string {
	if w.Expand == nil {
		return text
	}
	return w.Expand(text)
}

func (w World) isFile(path string) bool { return w.IsFile != nil && w.IsFile(path) }

// Tidy turns the forms a path takes in the registry into the ordinary one.
// Drivers and services are often recorded as \SystemRoot\System32\..., as
// \??\C:\..., or starting at System32 with no folder before it.
func (w World) Tidy(path string) string {
	path = winpath.Tidy(strings.Trim(strings.TrimSpace(w.expand(path)), `"`))
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, `\??\`), strings.HasPrefix(lower, `\\?\`):
		return path[4:]
	case strings.HasPrefix(lower, `\systemroot\`):
		return winpath.Join(w.Windows, path[len(`\systemroot\`):])
	case strings.HasPrefix(lower, `system32\`), strings.HasPrefix(lower, `syswow64\`):
		return winpath.Join(w.Windows, path)
	}
	return path
}

// Locate finds a program on disk from the name a command gives it, which
// may be a full path, or a bare name with or without ".exe". found is false
// when nothing is there, and the name is returned as it was given.
func (w World) Locate(name string) (path string, found bool) {
	path = w.Tidy(name)
	if path == "" {
		return "", false
	}
	try := func(candidate string) (string, bool) {
		if w.isFile(candidate) {
			return candidate, true
		}
		// Windows adds ".exe" to a name that has no ending.
		if winpath.Ext(candidate) == "" && w.isFile(candidate+".exe") {
			return candidate + ".exe", true
		}
		return candidate, false
	}
	if winpath.Absolute(path) {
		return try(path)
	}
	for _, folder := range w.Search {
		if at, ok := try(winpath.Join(folder, path)); ok {
			return at, true
		}
	}
	if w.AppPath != nil && !strings.ContainsAny(path, `\/`) {
		for _, name := range []string{path, path + ".exe"} {
			if registered := w.AppPath(name); registered != "" {
				if at, ok := try(w.Tidy(registered)); ok {
					return at, true
				}
			}
		}
	}
	return path, false
}

// Read takes a whole command line apart.
func (w World) Read(command string) Command {
	text := strings.TrimSpace(w.expand(command))
	if text == "" {
		return Command{}
	}
	if text[0] == '"' {
		if end := strings.IndexByte(text[1:], '"'); end >= 0 {
			return w.Launch(text[1:1+end], text[2+end:])
		}
		return w.Launch(text[1:], "")
	}
	// Without quotation marks, a path with spaces in it cannot be told from
	// a program followed by what it is told. Windows tries each place the
	// line could be cut, from the left, and takes the first that is a
	// program. So does this.
	for i := 0; i < len(text); i++ {
		if text[i] != ' ' && text[i] != '\t' {
			continue
		}
		if _, found := w.Locate(text[:i]); found {
			return w.Launch(text[:i], text[i:])
		}
	}
	if _, found := w.Locate(text); found {
		return w.Launch(text, "")
	}
	if cut := strings.IndexAny(text, " \t"); cut >= 0 {
		return w.Launch(text[:cut], text[cut:])
	}
	return w.Launch(text, "")
}

// Launch takes apart a command whose program and arguments are already
// separate, as they are in a scheduled task or a shortcut.
func (w World) Launch(program, arguments string) Command {
	c := Command{Arguments: strings.TrimSpace(w.expand(arguments))}
	c.Program, c.Found = w.Locate(program)
	w.follow(&c, 0)
	return c
}

// Words splits what a program is told into its words. A stretch inside
// quotation marks is one word, and the marks are dropped.
func Words(arguments string) []string {
	var words []string
	var word strings.Builder
	quoted, started := false, false
	for _, r := range arguments {
		switch {
		case r == '"':
			quoted, started = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteRune(r)
			started = true
		}
	}
	if started {
		words = append(words, word.String())
	}
	return words
}

// option reports whether a word is a switch, and returns its name in small
// letters without the dash or stroke in front.
func option(word string) (name string, ok bool) {
	if len(word) < 2 || (word[0] != '-' && word[0] != '/') {
		return "", false
	}
	return strings.ToLower(strings.TrimLeft(word, "-/")), true
}

// short reports whether a switch as typed stands for a full name. PowerShell
// takes any beginning of a name that is long enough to be told apart.
func short(typed, full string, least int) bool {
	return len(typed) >= least && strings.HasPrefix(full, typed)
}

// follow fills in what a go-between is handed.
func (w World) follow(c *Command, depth int) {
	words := Words(c.Arguments)
	switch winpath.Stem(c.Program) {
	case "rundll32":
		c.Carrier = Library
		library := rundllLibrary(c.Arguments)
		if lower := strings.ToLower(library); strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "vbscript:") || strings.HasPrefix(lower, "about:") {
			c.Carrier, c.Inline = Script, true // an old trick that makes rundll32 run script
			return
		}
		if library != "" {
			c.Target, _ = w.Locate(library)
		}
	case "regsvr32":
		c.Carrier = Library
		for _, word := range words {
			if _, isOption := option(word); !isOption {
				c.Target, _ = w.Locate(word)
			}
		}
	case "wscript", "cscript":
		c.Carrier = Script
		for _, word := range words {
			if !strings.HasPrefix(word, "/") {
				c.Target = w.Tidy(word)
				return
			}
		}
	case "powershell", "pwsh", "powershell_ise":
		c.Carrier = Script
		script, inline := powershellScript(words)
		if inline {
			// Commands on the line that do nothing but run one named script
			// are that script, and nothing is hidden.
			if file, ok := Loads(powershellCommand(words)); ok {
				script, inline = file, false
			}
		}
		c.Target, c.Inline = w.Tidy(script), inline
	case "cmd":
		c.Carrier = Script
		inner := cmdInner(c.Arguments)
		if inner == "" || depth >= 3 {
			return
		}
		// A word such as echo or set is carried out by cmd itself. There is
		// no program of that name to look for, even if one happens to exist.
		if builtIn(inner) {
			c.Inline = true
			return
		}
		next := w.Read(inner)
		if next.Found {
			c.Target = next.Works()
			c.Inline = next.Inline
		} else {
			c.Inline = true
		}
	case "mshta":
		c.Carrier = Script
		if len(words) > 0 {
			if at, found := w.Locate(words[0]); found {
				c.Target = at
			} else {
				c.Inline = true // an address on the internet, or script written on the line
			}
		}
	case "msiexec":
		c.Carrier = Package
		for i, word := range words {
			name, isOption := option(word)
			if !isOption {
				continue
			}
			if (name == "i" || name == "package" || name == "a") && i+1 < len(words) {
				c.Target = w.Tidy(words[i+1])
			} else if strings.HasPrefix(name, "i") && len(word) > 2 && strings.ContainsAny(word[2:], `\.`) {
				c.Target = w.Tidy(word[2:]) // written without a space: /iC:\thing.msi
			}
		}
	case "java", "javaw":
		c.Carrier = Package
		for i, word := range words {
			if word == "-jar" && i+1 < len(words) {
				c.Target = w.Tidy(words[i+1])
			}
		}
	case "python", "pythonw", "py", "node":
		c.Carrier = Script
		for _, word := range words {
			if word == "-c" || word == "-e" || word == "--eval" {
				c.Inline = true
				return
			}
			if !strings.HasPrefix(word, "-") {
				c.Target = w.Tidy(word)
				return
			}
		}
	case "conhost":
		// "conhost --headless" runs the rest with no window at all.
		if len(words) > 1 && strings.EqualFold(words[0], "--headless") && depth < 3 {
			rest := strings.TrimSpace(c.Arguments[strings.Index(strings.ToLower(c.Arguments), "--headless")+len("--headless"):])
			next := w.Read(rest)
			c.Carrier, c.Inline = Script, next.Inline
			if next.Found {
				c.Target = next.Works()
			}
		}
	}
}

// The commands cmd.exe carries out itself, without starting a program.
var builtIns = map[string]bool{}

func init() {
	for _, word := range strings.Fields(`assoc break call cd chdir cls color copy date del dir echo endlocal erase exit for ftype goto if md mkdir
		mklink move path pause popd prompt pushd rd rem ren rename rmdir set setlocal shift time title type ver verify vol`) {
		builtIns[word] = true
	}
}

// builtIn reports whether a command line for cmd begins with one of cmd's
// own commands.
func builtIn(command string) bool {
	word := strings.ToLower(strings.TrimLeft(strings.TrimSpace(command), "@("))
	for i, r := range word {
		if r < 'a' || r > 'z' {
			word = word[:i]
			break
		}
	}
	return builtIns[word]
}

// rundllLibrary picks the library out of what rundll32 is told, which has
// the form: library,entry and then anything else.
func rundllLibrary(arguments string) string {
	text := strings.TrimSpace(arguments)
	// rundll32 takes a few switches of its own before the library, such as /d.
	for len(text) > 1 && (text[0] == '/' || text[0] == '-') {
		text = dropWord(text)
	}
	if text == "" || text[0] == '{' {
		return "" // nothing, or the number of a Windows component instead of a file
	}
	if text[0] == '"' {
		if end := strings.IndexByte(text[1:], '"'); end >= 0 {
			return text[1 : 1+end]
		}
		return text[1:]
	}
	if cut := strings.IndexAny(text, ", \t"); cut >= 0 {
		return text[:cut]
	}
	return text
}

// powershellScript picks the script file out of what PowerShell is told.
// inline is true when it is given commands on the line itself instead.
func powershellScript(words []string) (script string, inline bool) {
	for i := 0; i < len(words); i++ {
		name, isOption := option(words[i])
		if !isOption {
			// The first word that is not a switch is the script or the command.
			if winpath.Ext(words[i]) == ".ps1" {
				return words[i], false
			}
			return "", true
		}
		switch {
		case short(name, "file", 1):
			if i+1 < len(words) {
				return words[i+1], false
			}
			return "", false
		case short(name, "executionpolicy", 2), name == "ep",
			short(name, "windowstyle", 1), short(name, "inputformat", 1), short(name, "outputformat", 1),
			short(name, "configurationname", 3), short(name, "version", 1), short(name, "psconsolefile", 1),
			short(name, "workingdirectory", 2), name == "wd", short(name, "settingsfile", 3), short(name, "custompipename", 3):
			i++ // these take a value, which is not the script
		case short(name, "command", 1), short(name, "encodedcommand", 1), name == "ec",
			short(name, "encodedarguments", 8), name == "ea":
			return "", true
		}
	}
	return "", false
}

// powershellCommand returns the commands PowerShell is given on the line
// itself: what follows -Command, or everything from the first word that is
// not a switch. It is empty when the commands are encoded or there are none.
func powershellCommand(words []string) string {
	for i := 0; i < len(words); i++ {
		name, isOption := option(words[i])
		if !isOption {
			return strings.Join(words[i:], " ")
		}
		switch {
		case short(name, "file", 1):
			return ""
		case short(name, "executionpolicy", 2), name == "ep",
			short(name, "windowstyle", 1), short(name, "inputformat", 1), short(name, "outputformat", 1),
			short(name, "configurationname", 3), short(name, "version", 1), short(name, "psconsolefile", 1),
			short(name, "workingdirectory", 2), name == "wd", short(name, "settingsfile", 3), short(name, "custompipename", 3):
			i++
		case short(name, "encodedcommand", 1), name == "ec", short(name, "encodedarguments", 8), name == "ea":
			return ""
		case short(name, "command", 1):
			return strings.Join(words[i+1:], " ")
		}
	}
	return ""
}

// PowerShellCommand returns the commands a whole PowerShell command line
// gives on the line itself, or "" when there are none to read.
func PowerShellCommand(line string) string {
	words := Words(line)
	if len(words) < 2 {
		return ""
	}
	switch winpath.Stem(words[0]) {
	case "powershell", "pwsh", "powershell_ise":
		return powershellCommand(words[1:])
	}
	return ""
}

// The ways a line of PowerShell runs one script file and does nothing else.
var loaders = []*regexp.Regexp{
	// iex([IO.File]::ReadAllText('C:\thing.ps1'))
	regexp.MustCompile(`(?i)^(?:iex|invoke-expression)\s*\(?\s*\[(?:system\.)?io\.file\]::readalltext\(\s*['"]?([^'"()|;]+?)['"]?\s*\)\s*\)?$`),
	// Get-Content 'C:\thing.ps1' -Raw | iex
	regexp.MustCompile(`(?i)^(?:get-content|gc|cat|type)\s+(?:-(?:literal)?path\s+)?['"]?([^'"()|;]+?)['"]?(?:\s+-raw)?\s*\|\s*(?:iex|invoke-expression)$`),
	// iex (Get-Content 'C:\thing.ps1' -Raw)
	regexp.MustCompile(`(?i)^(?:iex|invoke-expression)\s*\(\s*(?:get-content|gc|cat|type)\s+(?:-(?:literal)?path\s+)?['"]?([^'"()|;]+?)['"]?(?:\s+-raw)?\s*\)$`),
	// & 'C:\thing.ps1' and . 'C:\thing.ps1', with or without something handed to it
	regexp.MustCompile(`(?i)^[&.]\s*'([^'()|;]+\.ps1)'(?:\s+[^|;&` + "`" + `$()]*)?$`),
	regexp.MustCompile(`(?i)^[&.]\s+([^\s'"()|;]+\.ps1)(?:\s+[^|;&` + "`" + `$()]*)?$`),
	// C:\thing.ps1 alone
	regexp.MustCompile(`(?i)^'?([^\s'"()|;]+\.ps1)'?$`),
}

// Loads reports whether commands given to PowerShell on the line do nothing
// but run one script file, and names that file. Such a line hides nothing:
// what it does is whatever the file says, and the file can be read.
func Loads(commands string) (file string, ok bool) {
	text := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(commands), ";"))
	// One pair of braces or brackets around everything changes nothing.
	for len(text) > 2 && ((text[0] == '{' && text[len(text)-1] == '}') || (text[0] == '(' && text[len(text)-1] == ')' && strings.Count(text, "(") == 1)) {
		text = strings.TrimSpace(text[1 : len(text)-1])
	}
	if strings.HasPrefix(text, "&") && len(text) > 3 && text[len(text)-1] == '}' {
		// & { ... }
		if rest := strings.TrimSpace(text[1:]); strings.HasPrefix(rest, "{") {
			text = strings.TrimSpace(rest[1 : len(rest)-1])
		}
	}
	for _, loader := range loaders {
		if found := loader.FindStringSubmatch(text); found != nil {
			if file = strings.TrimSpace(found[1]); file != "" && !strings.ContainsAny(file, "$*?<>") {
				return file, true
			}
		}
	}
	return "", false
}

// cmdInner returns the command that cmd.exe is told to run with /c or /k,
// without the "start" that often comes first.
func cmdInner(arguments string) string {
	lower := strings.ToLower(arguments)
	inner := ""
	for i := 0; i+1 < len(lower); i++ {
		if lower[i] == '/' && (lower[i+1] == 'c' || lower[i+1] == 'k') && (i == 0 || lower[i-1] == ' ' || lower[i-1] == '\t') {
			inner = strings.TrimSpace(arguments[i+2:])
			break
		}
	}
	// cmd drops one pair of quotation marks from around the whole command.
	if strings.HasPrefix(inner, `""`) && strings.HasSuffix(inner, `"`) && len(inner) > 2 {
		inner = strings.TrimSpace(inner[1 : len(inner)-1])
	}
	if len(inner) > 6 && strings.EqualFold(inner[:6], "start ") {
		inner = strings.TrimSpace(inner[6:])
		titled := false
		for inner != "" {
			switch {
			case inner[0] == '/':
				// A switch of start, such as /min. /d is followed by a folder.
				word := inner
				if cut := strings.IndexAny(inner, " \t"); cut >= 0 {
					word, inner = inner[:cut], strings.TrimSpace(inner[cut:])
				} else {
					inner = ""
				}
				if strings.EqualFold(word, "/d") {
					inner = dropWord(inner)
				}
				continue
			case inner[0] == '"' && !titled:
				// The first thing in quotation marks is the title of the new window.
				titled = true
				if rest := dropWord(inner); rest != "" {
					inner = rest
					continue
				}
			}
			break
		}
	}
	return inner
}

// dropWord returns a line without its first word, which may be in
// quotation marks.
func dropWord(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if text[0] == '"' {
		if end := strings.IndexByte(text[1:], '"'); end >= 0 {
			return strings.TrimSpace(text[2+end:])
		}
		return ""
	}
	if cut := strings.IndexAny(text, " \t"); cut >= 0 {
		return strings.TrimSpace(text[cut:])
	}
	return ""
}
