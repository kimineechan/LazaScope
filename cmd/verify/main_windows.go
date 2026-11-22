//go:build windows

// verify proves on a real PC that LazaScope notices what it should.
//
// It plants eleven harmless things: ten that look suspicious, and one that
// does not. It takes a look, checks that each of the ten was listed and
// flagged for the right reason and that the eleventh was listed and left
// alone, then removes them all and checks that none is left.
//
// Everything it plants belongs to the account that runs it: lines in that
// account's own Run and RunOnce lists, files in its own temporary and
// Downloads folders, a shortcut and a batch file in its own Startup folder,
// and two programs of its own that wait and do nothing. Nothing for the
// whole PC is touched, and no administrator rights are needed. The planted
// files are copies of Notepad and of the Command Prompt, and of this
// program itself, which does nothing when started from where it was
// planted.
//
// LazaScope itself never writes anything. The writing is all here.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"lazascope/internal/com"
	"lazascope/internal/model"
	"lazascope/internal/pcinfo"
	"lazascope/internal/rules"
	"lazascope/internal/scan"
	"lazascope/internal/sigcheck"
	"lazascope/internal/sysdll"
)

// Everything planted carries this name, so that it can be found again and
// nothing else is ever removed.
const mark = "LazaScope planted"

const (
	runList     = `Software\Microsoft\Windows\CurrentVersion\Run`
	runOnceList = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
)

var (
	advapi32    = sysdll.Load("advapi32.dll")
	createKey   = advapi32.NewProc("RegCreateKeyExW")
	setValue    = advapi32.NewProc("RegSetValueExW")
	deleteValue = advapi32.NewProc("RegDeleteValueW")
)

// The lines planted in the Run list, by the end of their names.
var runLines = []string{" disguise", " lookalike", " download", " leftover", " scramble", " plain"}

// plant is one planted thing and what must be said about it.
type plant struct {
	what    string            // what it is, in plain words
	subject string            // the name it goes by in LazaScope's lists and findings
	kind    model.StartupKind // the kind of start-up entry it must be listed as
	running bool              // it is a running program, not a start-up entry
	file    string            // the file LazaScope must name as doing the work, or "" when there is none to name
	rules   []string          // the rules that must flag it; none means it must be left alone
}

// places are the folders the planted things go in.
type places struct {
	temp, downloads, startup, system string
}

func (p places) shortcut() string { return filepath.Join(p.startup, mark+" shortcut.lnk") }
func (p places) note() string     { return filepath.Join(p.startup, mark+" note.cmd") }

func main() {
	self, _ := os.Executable()
	// A copy of this program is one of the planted files. Started from
	// there it must do nothing at all: it waits when told to, and ends.
	if strings.Contains(self, mark) {
		if len(os.Args) > 1 && os.Args[1] == "--wait" {
			io.Copy(io.Discard, os.Stdin)
		}
		return
	}
	if err := run(self); err != nil {
		fmt.Println()
		fmt.Println("FAILED:", err)
		os.Exit(1)
	}
}

func run(self string) error {
	fmt.Println("LazaScope verification")
	fmt.Println()
	if err := signatures(self); err != nil {
		return err
	}
	p := places{
		temp:      filepath.Join(os.TempDir(), mark),
		downloads: filepath.Join(pcinfo.KnownFolder(pcinfo.Downloads), mark),
		startup:   pcinfo.KnownFolder(pcinfo.UserStartup),
		system:    sysdll.Folder(),
	}
	if p.startup == "" || !filepath.IsAbs(p.downloads) || !filepath.IsAbs(p.temp) {
		return errors.New("this account's Downloads or Startup folder could not be found")
	}
	// Anything an earlier run left behind goes first.
	if err := remove(p); err != nil {
		return fmt.Errorf("leftovers of an earlier run could not be removed: %w", err)
	}
	plants, stop, err := put(p, self)
	// Whatever happens from here, the planted things are removed again.
	defer func() {
		stop()
		if err := remove(p); err != nil {
			fmt.Println("FAILED to remove a planted item:", err)
			os.Exit(1)
		}
	}()
	if err != nil {
		return fmt.Errorf("a harmless item could not be planted: %w", err)
	}
	before := present(p)
	fmt.Printf("Planted %d harmless items in this account's own Run lists and folders.\n", len(plants))

	s := scan.Run(scan.Everything, nil)
	findings := rules.Check(s)
	fmt.Printf("Looked at the PC: %d start-up entries, %d running programs, %d connections, %d findings, in %d ms.\n\n",
		len(s.Startup), len(s.Processes), len(s.Connections), len(findings), s.Took.Milliseconds())
	if len(s.Startup) < 20 || len(s.Processes) < 10 || s.Guard.Build == "" {
		return errors.New("the look came back nearly empty, so the collectors are not working")
	}
	// Looking must not have changed what was planted.
	if after := present(p); strings.Join(after, "|") != strings.Join(before, "|") {
		return fmt.Errorf("before the look %d planted things were there, after it %d: looking changed something", len(before), len(after))
	}

	missed := 0
	fail := func(format string, values ...any) {
		missed++
		fmt.Printf("    "+format+"\n", values...)
	}
	for _, item := range plants {
		fmt.Println(item.what)
		// First, is it in the list at all, as the right kind of thing and
		// with the right file?
		switch where, file, found := listed(s, item); {
		case !found:
			fail("NOT LISTED")
		case item.file != "" && !strings.EqualFold(file, item.file):
			fail("LISTED WITH THE WRONG FILE: %s, want %s", file, item.file)
		default:
			fmt.Printf("    listed under %s\n", where)
		}
		// Then, what was said about it.
		for _, rule := range item.rules {
			if title, ok := flagged(findings, item.subject, rule); ok {
				fmt.Printf("    flagged: %s\n", title)
			} else {
				fail("NOT FLAGGED by the rule %s", rule)
			}
		}
		if len(item.rules) == 0 {
			fmt.Println("    left alone, as it should be")
		}
	}
	// Anything else said about a planted thing would be a rule firing where
	// it should not.
	for _, f := range findings {
		if planted(plants, f.Subject) && !expected(plants, f) {
			fail("UNEXPECTED: %s was also flagged by %s", f.Subject, f.Rule)
		}
	}

	stop()
	if err := remove(p); err != nil {
		return fmt.Errorf("a planted item could not be removed: %w", err)
	}
	if left := present(p); len(left) != 0 {
		return fmt.Errorf("%d planted things are still there after removal, for example %s", len(left), left[0])
	}
	fmt.Println()
	fmt.Println("Removed every planted item and checked that none is left.")
	if missed > 0 {
		return fmt.Errorf("%d checks did not come out as they should", missed)
	}
	fmt.Printf("All %d planted items came out as they should.\n", len(plants))
	return nil
}

// signatures checks the signature checker against files whose answer is
// known: a part of Windows, and this program, which nobody has signed.
func signatures(self string) error {
	checker := sigcheck.New()
	defer checker.Close()
	windows := checker.Check(filepath.Join(sysdll.Folder(), "cmd.exe"))
	if windows.Status != sigcheck.Signed || !windows.FromWindows() {
		return fmt.Errorf("the Command Prompt came out as %q by %q: the signature checker is not working", windows.Status, windows.Signer)
	}
	if own := checker.Check(self); own.Status != sigcheck.Unsigned {
		return fmt.Errorf("this unsigned program came out as %q", own.Status)
	}
	fmt.Printf("Signature checker: a part of Windows is signed by %s (%s), and an unsigned program is not signed.\n", windows.Signer, windows.Source)
	return nil
}

// listed looks for a planted thing in what LazaScope read, and returns
// where it was found and the file LazaScope names for it.
func listed(s *model.Snapshot, item plant) (where, file string, found bool) {
	if item.running {
		for _, p := range s.Processes {
			if strings.EqualFold(p.Name, item.subject) && strings.Contains(p.File.Path, mark) {
				return "running programs", p.File.Path, true
			}
		}
		return "", "", false
	}
	for _, e := range s.Startup {
		if e.Kind == item.kind && e.Shown() == item.subject && e.Enabled {
			return e.Kind.String(), e.Works().Path, true
		}
	}
	return "", "", false
}

func flagged(findings []rules.Finding, subject, rule string) (title string, ok bool) {
	for _, f := range findings {
		if f.Subject == subject && f.Rule == rule {
			return f.Title, true
		}
	}
	return "", false
}

func planted(plants []plant, subject string) bool {
	for _, item := range plants {
		if item.subject == subject {
			return true
		}
	}
	return false
}

func expected(plants []plant, f rules.Finding) bool {
	for _, item := range plants {
		if item.subject != f.Subject {
			continue
		}
		for _, rule := range item.rules {
			if rule == f.Rule {
				return true
			}
		}
	}
	return false
}

// wait starts a planted program that does nothing but wait, with no window,
// and returns the way to end it.
func wait(program string, arguments ...string) (stop func(), err error) {
	waiting := exec.Command(program, arguments...)
	waiting.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	input, err := waiting.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := waiting.Start(); err != nil {
		return nil, err
	}
	return func() {
		io.WriteString(input, "\r\n")
		input.Close()
		done := make(chan struct{})
		go func() { waiting.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			waiting.Process.Kill()
			<-done
		}
	}, nil
}

// put plants everything. stop ends the two planted programs that run.
func put(p places, self string) (plants []plant, stop func(), err error) {
	var stops []func()
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			for _, end := range stops {
				end()
			}
		}
	}
	for _, folder := range []string{p.temp, p.downloads} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			return nil, stop, err
		}
	}
	notepad, prompt := filepath.Join(p.system, "notepad.exe"), filepath.Join(p.system, "cmd.exe")
	disguise, lookalike := filepath.Join(p.temp, "svchost.exe"), filepath.Join(p.temp, "scvhost.exe")
	running, download := filepath.Join(p.temp, "lsass.exe"), filepath.Join(p.downloads, "freebie.exe")
	for _, file := range [][2]string{{notepad, disguise}, {notepad, lookalike}, {prompt, running}, {self, download}} {
		if err := copyFile(file[0], file[1]); err != nil {
			return nil, stop, err
		}
	}
	gone := filepath.Join(filepath.Dir(os.TempDir()), mark, "gone.exe") // never made
	for _, line := range [][2]string{
		{mark + " disguise", `"` + disguise + `"`},
		{mark + " lookalike", `"` + lookalike + `"`},
		{mark + " download", `"` + download + `" --idle`},
		{mark + " leftover", `"` + gone + `" /tray`},
		{mark + " scramble", `cmd.exe /c echo %COMSPEC:~0,1%`},
		// The one that must stay quiet: a part of Windows, started from where
		// Windows keeps it.
		{mark + " plain", `"` + notepad + `"`},
	} {
		if err := setValueIn(runList, line[0], line[1]); err != nil {
			return nil, stop, err
		}
	}
	if err := setValueIn(runOnceList, mark+" once", `"`+download+`" --idle`); err != nil {
		return nil, stop, err
	}
	if err := makeShortcut(p.shortcut(), download, "--idle"); err != nil {
		return nil, stop, err
	}
	// A batch file that does nothing. A script that starts by itself is
	// worth a look whatever is in it, because nothing shows who wrote it.
	if err := os.WriteFile(p.note(), []byte("@rem "+mark+": a harmless test item. It does nothing and is safe to delete.\r\n"), 0o600); err != nil {
		return nil, stop, err
	}
	// Two planted programs are started, to be seen running. Both show no
	// window, do nothing, and end when told: a copy of the Command Prompt
	// told to wait, and the unsigned program from Downloads.
	for _, program := range [][]string{{running, "/c", "pause"}, {download, "--wait"}} {
		end, err := wait(program[0], program[1:]...)
		if err != nil {
			return nil, stop, err
		}
		stops = append(stops, end)
	}
	time.Sleep(300 * time.Millisecond) // let them get going before the look

	return []plant{
		{what: "A copy of Notepad named svchost.exe in the temporary folder, set to start at sign-in",
			subject: mark + " disguise", kind: model.RunKey, file: disguise, rules: []string{"startup-system-name", "startup-temp-folder"}},
		{what: "A copy of Notepad named scvhost.exe, one slip from svchost, set to start at sign-in",
			subject: mark + " lookalike", kind: model.RunKey, file: lookalike, rules: []string{"startup-system-name", "startup-temp-folder"}},
		{what: "An unsigned program in the Downloads folder, set to start at sign-in",
			subject: mark + " download", kind: model.RunKey, file: download, rules: []string{"startup-temp-folder", "startup-unsigned"}},
		{what: "The same program, set to start once at the next sign-in",
			subject: mark + " once", kind: model.RunOnceKey, file: download, rules: []string{"startup-temp-folder", "startup-unsigned"}},
		{what: "A start-up line that points at a file that is not there",
			subject: mark + " leftover", kind: model.RunKey, file: gone, rules: []string{"startup-missing-file"}},
		{what: "A start-up line that runs the Command Prompt with its words broken up",
			subject: mark + " scramble", kind: model.RunKey, file: prompt, rules: []string{"startup-scrambled-command"}},
		{what: "A shortcut in the Startup folder to the unsigned program in Downloads",
			subject: mark + " shortcut.lnk", kind: model.StartupFolder, file: download, rules: []string{"startup-temp-folder", "startup-unsigned"}},
		{what: "A batch file in the Startup folder",
			subject: mark + " note.cmd", kind: model.StartupFolder, file: p.note(), rules: []string{"startup-script"}},
		{what: "A start-up line for the real Notepad, in the Windows folder",
			subject: mark + " plain", kind: model.RunKey, file: notepad},
		{what: "A copy of the Command Prompt named lsass.exe, running from the temporary folder",
			subject: "lsass.exe", running: true, file: running, rules: []string{"running-system-name", "running-temp-folder"}},
		{what: "The unsigned program, running from the Downloads folder",
			subject: "freebie.exe", running: true, file: download, rules: []string{"running-temp-folder"}},
	}, stop, nil
}

// present lists what is there of the planted things: every line, every
// file, the shortcut and the batch file.
func present(p places) []string {
	var found []string
	for list, names := range map[string][]string{runList: runLines, runOnceList: {" once"}} {
		key, err := open(list)
		if err != nil {
			continue
		}
		for _, name := range names {
			wide, _ := syscall.UTF16PtrFromString(mark + name)
			if syscall.RegQueryValueEx(key, wide, nil, nil, nil, nil) == nil {
				found = append(found, "the line "+mark+name)
			}
		}
		syscall.RegCloseKey(key)
	}
	for _, path := range []string{p.shortcut(), p.note(), filepath.Join(p.temp, "svchost.exe"), filepath.Join(p.temp, "scvhost.exe"), filepath.Join(p.temp, "lsass.exe"), filepath.Join(p.downloads, "freebie.exe")} {
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	for _, folder := range []string{p.temp, p.downloads} {
		if _, err := os.Stat(folder); err == nil {
			found = append(found, folder)
		}
	}
	return found
}

// remove takes away everything put could have planted, and nothing else.
func remove(p places) error {
	for list, names := range map[string][]string{runList: runLines, runOnceList: {" once"}} {
		key, err := open(list)
		if err != nil {
			continue
		}
		for _, name := range names {
			wide, _ := syscall.UTF16PtrFromString(mark + name)
			deleteValue.Call(uintptr(key), uintptr(unsafe.Pointer(wide)))
		}
		syscall.RegCloseKey(key)
	}
	for _, path := range []string{p.shortcut(), p.note()} {
		// Only a file with the planted name is ever removed.
		if !strings.HasPrefix(filepath.Base(path), mark) {
			return fmt.Errorf("refusing to remove %s", path)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	for _, folder := range []string{p.temp, p.downloads} {
		// Only a folder with the planted name is ever removed.
		if filepath.Base(folder) != mark {
			return fmt.Errorf("refusing to remove %s", folder)
		}
		var err error
		for range 15 {
			if err = os.RemoveAll(folder); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond) // a program that has just ended still holds its file for a moment
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// open opens one of this account's own start-up lists for writing, making
// it if this account has never had one.
func open(list string) (syscall.Handle, error) {
	path, _ := syscall.UTF16PtrFromString(list)
	const query, set = 0x1, 0x2
	var key syscall.Handle
	if r, _, _ := createKey.Call(uintptr(syscall.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(path)), 0, 0, 0, query|set, 0, uintptr(unsafe.Pointer(&key)), 0); r != 0 {
		return 0, syscall.Errno(r)
	}
	return key, nil
}

func setValueIn(list, name, command string) error {
	key, err := open(list)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(key)
	wideName, _ := syscall.UTF16PtrFromString(name)
	data, err := syscall.UTF16FromString(command)
	if err != nil {
		return err
	}
	const text = 1
	if r, _, _ := setValue.Call(uintptr(key), uintptr(unsafe.Pointer(wideName)), 0, text, uintptr(unsafe.Pointer(&data[0])), uintptr(2*len(data))); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func copyFile(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, data, 0o700)
}

// makeShortcut writes a shortcut file, the way Explorer does.
func makeShortcut(path, target, arguments string) error {
	leave, err := com.Enter()
	defer leave()
	if err != nil {
		return err
	}
	link, err := com.Create(com.ID("00021401-0000-0000-C000-000000000046"), com.ID("000214F9-0000-0000-C000-000000000046"))
	if err != nil {
		return err
	}
	defer link.Release()
	const setArguments, setPath, save = 11, 20, 6
	wideTarget, _ := syscall.UTF16PtrFromString(target)
	wideArguments, _ := syscall.UTF16PtrFromString(arguments)
	if r := link.Call(setPath, uintptr(unsafe.Pointer(wideTarget))); com.Failed(r) {
		return fmt.Errorf("the shortcut would not take its target (0x%08X)", uint32(r))
	}
	link.Call(setArguments, uintptr(unsafe.Pointer(wideArguments)))
	file, err := link.Ask(com.ID("0000010B-0000-0000-C000-000000000046"))
	if err != nil {
		return err
	}
	defer file.Release()
	widePath, _ := syscall.UTF16PtrFromString(path)
	if r := file.Call(save, uintptr(unsafe.Pointer(widePath)), 1); com.Failed(r) {
		return fmt.Errorf("the shortcut could not be saved (0x%08X)", uint32(r))
	}
	return nil
}
