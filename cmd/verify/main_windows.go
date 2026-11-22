//go:build windows

// verify proves on a real PC that LazaScope notices what it should.
//
// It plants a handful of harmless things that look suspicious, takes a
// look, checks that every one of them was flagged for the right reason,
// then removes them all and checks that none is left.
//
// Everything it plants belongs to the account that runs it: lines in that
// account's own Run list, files in its own temporary and Downloads folders,
// a shortcut in its own Startup folder and one program of its own. Nothing
// for the whole PC is touched, and no administrator rights are needed. The
// planted files are copies of Notepad and of the Command Prompt, and of
// this program itself, which does nothing when started from where it was
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
	"lazascope/internal/pcinfo"
	"lazascope/internal/rules"
	"lazascope/internal/scan"
	"lazascope/internal/sigcheck"
	"lazascope/internal/sysdll"
)

// Everything planted carries this name, so that it can be found again and
// nothing else is ever removed.
const mark = "LazaScope planted"

const runList = `Software\Microsoft\Windows\CurrentVersion\Run`

var (
	advapi32    = sysdll.Load("advapi32.dll")
	createKey   = advapi32.NewProc("RegCreateKeyExW")
	setValue    = advapi32.NewProc("RegSetValueExW")
	deleteValue = advapi32.NewProc("RegDeleteValueW")
)

// plant is one planted thing and what must be said about it.
type plant struct {
	what    string   // what it is, in plain words
	subject string   // the name it goes by in LazaScope's findings
	rules   []string // the rules that must flag it
}

// places are the folders the planted files go in.
type places struct {
	temp, downloads, startup, system string
}

func (p places) shortcut() string { return filepath.Join(p.startup, mark+" shortcut.lnk") }

func main() {
	self, _ := os.Executable()
	// A copy of this program is one of the planted files. Started from
	// there, it must do nothing at all.
	if strings.Contains(self, mark) {
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
	fmt.Printf("Planted %d harmless items in this account's own Run list and folders.\n", len(plants))

	s := scan.Run(scan.Everything, nil)
	findings := rules.Check(s)
	fmt.Printf("Looked at the PC: %d start-up entries, %d running programs, %d connections, %d findings, in %d ms.\n\n",
		len(s.Startup), len(s.Processes), len(s.Connections), len(findings), s.Took.Milliseconds())
	if len(s.Startup) < 20 || len(s.Processes) < 10 || s.Guard.Build == "" {
		return errors.New("the look came back nearly empty, so the collectors are not working")
	}
	// Looking must not have changed what was planted.
	if still, _ := planted(p); still != len(plants) {
		return fmt.Errorf("after the look, %d of the %d planted items are still there: looking changed something", still, len(plants))
	}

	missed := 0
	for _, item := range plants {
		fmt.Println(item.what)
		for _, rule := range item.rules {
			title, ok := flagged(findings, item.subject, rule)
			if !ok {
				missed++
				fmt.Printf("    NOT FLAGGED by the rule %s\n", rule)
				continue
			}
			fmt.Printf("    flagged: %s\n", title)
		}
	}
	// Whatever else was flagged with the planted name would be a rule
	// firing where it should not.
	for _, f := range findings {
		if strings.Contains(f.Subject, mark) && !expected(plants, f) {
			missed++
			fmt.Printf("UNEXPECTED: %s was also flagged by %s\n", f.Subject, f.Rule)
		}
	}

	stop()
	if err := remove(p); err != nil {
		return fmt.Errorf("a planted item could not be removed: %w", err)
	}
	if left, where := planted(p); left != 0 {
		return fmt.Errorf("%d planted items are still there after removal, for example %s", left, where)
	}
	fmt.Println()
	fmt.Println("Removed every planted item and checked that none is left.")
	if missed > 0 {
		return fmt.Errorf("%d checks did not come out as they should", missed)
	}
	fmt.Printf("All %d planted items were flagged for the right reasons.\n", len(plants))
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

func flagged(findings []rules.Finding, subject, rule string) (title string, ok bool) {
	for _, f := range findings {
		if f.Subject == subject && f.Rule == rule {
			return f.Title, true
		}
	}
	return "", false
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

// put plants everything. stop ends the one planted program that runs.
func put(p places, self string) (plants []plant, stop func(), err error) {
	stop = func() {}
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
	} {
		if err := setRun(line[0], line[1]); err != nil {
			return nil, stop, err
		}
	}
	if err := makeShortcut(p.shortcut(), download, "--idle"); err != nil {
		return nil, stop, err
	}
	// One planted program is started, to be seen running: the copy of the
	// Command Prompt, told to wait. It shows no window and ends when told.
	waiting := exec.Command(running, "/c", "pause")
	waiting.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	input, err := waiting.StdinPipe()
	if err != nil {
		return nil, stop, err
	}
	if err := waiting.Start(); err != nil {
		return nil, stop, err
	}
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
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
	}
	time.Sleep(300 * time.Millisecond) // let it get going before the look

	return []plant{
		{"A copy of Notepad named svchost.exe in the temporary folder, set to start at sign-in", mark + " disguise", []string{"startup-system-name", "startup-temp-folder"}},
		{"A copy of Notepad named scvhost.exe, one slip from svchost, set to start at sign-in", mark + " lookalike", []string{"startup-system-name", "startup-temp-folder"}},
		{"An unsigned program in the Downloads folder, set to start at sign-in", mark + " download", []string{"startup-temp-folder", "startup-unsigned"}},
		{"A start-up line that points at a file that is not there", mark + " leftover", []string{"startup-missing-file"}},
		{"A start-up line that runs the Command Prompt with its words broken up", mark + " scramble", []string{"startup-scrambled-command"}},
		{"A shortcut in the Startup folder to the unsigned program in Downloads", mark + " shortcut.lnk", []string{"startup-temp-folder", "startup-unsigned"}},
		{"A copy of the Command Prompt named lsass.exe, running from the temporary folder", "lsass.exe", []string{"running-system-name", "running-temp-folder"}},
	}, stop, nil
}

// planted counts what is there of the planted things, and names one.
func planted(p places) (count int, example string) {
	note := func(where string) {
		count++
		example = where
	}
	if key, err := openRun(); err == nil {
		defer syscall.RegCloseKey(key)
		for _, name := range []string{" disguise", " lookalike", " download", " leftover", " scramble"} {
			wide, _ := syscall.UTF16PtrFromString(mark + name)
			if syscall.RegQueryValueEx(key, wide, nil, nil, nil, nil) == nil {
				note("the Run line " + mark + name)
			}
		}
	}
	if _, err := os.Stat(p.shortcut()); err == nil {
		note(p.shortcut())
	}
	// The program that runs counts as one with the folder it runs from.
	if _, err := os.Stat(filepath.Join(p.temp, "lsass.exe")); err == nil {
		note(filepath.Join(p.temp, "lsass.exe"))
	}
	return count, example
}

// remove takes away everything put could have planted, and nothing else.
func remove(p places) error {
	if key, err := openRun(); err == nil {
		for _, name := range []string{" disguise", " lookalike", " download", " leftover", " scramble"} {
			wide, _ := syscall.UTF16PtrFromString(mark + name)
			deleteValue.Call(uintptr(key), uintptr(unsafe.Pointer(wide)))
		}
		syscall.RegCloseKey(key)
	}
	if err := os.Remove(p.shortcut()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, folder := range []string{p.temp, p.downloads} {
		// Only a folder with the planted name is ever removed.
		if filepath.Base(folder) != mark {
			return fmt.Errorf("refusing to remove %s", folder)
		}
		var err error
		for range 10 {
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

// openRun opens this account's Run list for writing, making it if this
// account has never had one.
func openRun() (syscall.Handle, error) {
	path, _ := syscall.UTF16PtrFromString(runList)
	const query, set = 0x1, 0x2
	var key syscall.Handle
	if r, _, _ := createKey.Call(uintptr(syscall.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(path)), 0, 0, 0, query|set, 0, uintptr(unsafe.Pointer(&key)), 0); r != 0 {
		return 0, syscall.Errno(r)
	}
	return key, nil
}

func setRun(name, command string) error {
	key, err := openRun()
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
