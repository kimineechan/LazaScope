//go:build windows

// Package pcinfo answers the general questions about this PC that the
// collectors share: where its folders are, who is signed in, and whether
// the program has administrator rights.
package pcinfo

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"lazascope/internal/cmdline"
	"lazascope/internal/model"
	"lazascope/internal/reg"
	"lazascope/internal/sysdll"
	"lazascope/internal/winpath"
)

var (
	kernel32 = sysdll.Load("kernel32.dll")
	shell32  = sysdll.Load("shell32.dll")
	shlwapi  = sysdll.Load("shlwapi.dll")
	ole32    = sysdll.Load("ole32.dll")

	expandStrings  = kernel32.NewProc("ExpandEnvironmentStringsW")
	knownFolder    = shell32.NewProc("SHGetKnownFolderPath")
	indirectString = shlwapi.NewProc("SHLoadIndirectString")
	taskFree       = ole32.NewProc("CoTaskMemFree")
)

// Expand fills in names such as %SystemRoot% with their values.
func Expand(text string) string {
	if !strings.Contains(text, "%") {
		return text
	}
	source, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return text
	}
	buffer := make([]uint16, 1024)
	for range 3 {
		n, _, _ := expandStrings.Call(uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if n == 0 {
			return text
		}
		if int(n) <= len(buffer) {
			return syscall.UTF16ToString(buffer)
		}
		buffer = make([]uint16, n+1)
	}
	return text
}

// Indirect resolves the names Windows stores as a pointer into a program
// file, such as "@%SystemRoot%\system32\thing.dll,-100", into the text a
// person reads. Text of any other form comes back unchanged.
func Indirect(text string) string {
	text = strings.TrimSpace(text)
	// Task Scheduler wraps the same form in $( ).
	if strings.HasPrefix(text, "$(@") && strings.HasSuffix(text, ")") {
		text = text[2 : len(text)-1]
	}
	if !strings.HasPrefix(text, "@") {
		return text
	}
	source, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return text
	}
	buffer := make([]uint16, 2048)
	if r, _, _ := indirectString.Call(uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0); r != 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}

type folderID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// The names Windows gives the folders asked for by KnownFolder.
var (
	Downloads     = folderID{0x374DE290, 0x123F, 0x4565, [8]byte{0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}}
	UserStartup   = folderID{0xB97D20BB, 0xF46A, 0x4C97, [8]byte{0xBA, 0x10, 0x5E, 0x36, 0x08, 0x43, 0x08, 0x54}}
	CommonStartup = folderID{0x82A5EA35, 0xD9CD, 0x47C5, [8]byte{0x96, 0x29, 0xE1, 0x5D, 0x2F, 0x71, 0x4E, 0x6E}}
)

// KnownFolder returns where one of Windows' named folders is on this PC, or
// "" when Windows cannot say.
func KnownFolder(id folderID) string {
	var path *uint16
	r, _, _ := knownFolder.Call(uintptr(unsafe.Pointer(&id)), 0, 0, uintptr(unsafe.Pointer(&path)))
	if path == nil {
		return ""
	}
	defer taskFree.Call(uintptr(unsafe.Pointer(path)))
	if r != 0 {
		return ""
	}
	return syscall.UTF16ToString((*[32768]uint16)(unsafe.Pointer(path))[:])
}

// Folders returns the places on this PC that the rules know by name.
func Folders() model.Folders {
	windows := os.Getenv("SystemRoot")
	if windows == "" {
		windows = winpath.Dir(sysdll.Folder())
	}
	profile := os.Getenv("USERPROFILE")
	f := model.Folders{
		Windows:         windows,
		System:          sysdll.Folder(),
		ProgramFiles:    os.Getenv("ProgramW6432"),
		ProgramFilesX86: os.Getenv("ProgramFiles(x86)"),
		ProgramData:     os.Getenv("ProgramData"),
		Profile:         profile,
		Users:           winpath.Dir(profile),
		Temp:            winpath.Tidy(os.TempDir()),
		Downloads:       KnownFolder(Downloads),
	}
	if f.ProgramFiles == "" {
		f.ProgramFiles = os.Getenv("ProgramFiles")
	}
	if f.Downloads == "" && profile != "" {
		f.Downloads = winpath.Join(profile, "Downloads")
	}
	return f
}

// World returns what reading a command needs to know about this PC.
func World() cmdline.World {
	folders := Folders()
	search := []string{folders.System, folders.Windows}
	for _, folder := range strings.Split(os.Getenv("PATH"), ";") {
		if folder = strings.TrimSpace(folder); folder != "" {
			search = append(search, folder)
		}
	}
	return cmdline.World{
		Expand: Expand,
		IsFile: func(path string) bool {
			info, err := os.Stat(path)
			return err == nil && !info.IsDir()
		},
		Windows: folders.Windows,
		Search:  search,
		AppPath: func(name string) string {
			// Programs register their place here so that typing the bare
			// name in the Run box finds them.
			const key = `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`
			for _, root := range []syscall.Handle{reg.User, reg.Machine} {
				for _, view := range []reg.View{reg.Native, reg.Compat} {
					if path, ok := reg.Text(root, key+name, view, ""); ok && path != "" {
						return path
					}
				}
			}
			return ""
		},
	}
}

// Elevated reports whether this program is running with administrator
// rights.
func Elevated() bool {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	const elevation = 20 // TokenElevation
	var raised, size uint32
	if err := syscall.GetTokenInformation(token, elevation, (*byte)(unsafe.Pointer(&raised)), 4, &size); err != nil {
		return false
	}
	return raised != 0
}

// Describe returns the name of the PC, the account in use and the version
// of Windows.
func Describe() (computer, user, windows string) {
	computer, _ = os.Hostname()
	user = os.Getenv("USERNAME")
	if domain := os.Getenv("USERDOMAIN"); domain != "" && !strings.EqualFold(domain, computer) {
		user = domain + `\` + user
	}
	const current = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	windows, _ = reg.Text(reg.Machine, current, reg.Native, "ProductName")
	build, _ := reg.Text(reg.Machine, current, reg.Native, "CurrentBuild")
	// Windows 11 still calls itself Windows 10 here. The build number tells.
	if number, _ := strconv.Atoi(build); number >= 22000 {
		windows = strings.Replace(windows, "Windows 10", "Windows 11", 1)
	}
	if release, ok := reg.Text(reg.Machine, current, reg.Native, "DisplayVersion"); ok && release != "" {
		windows += " " + release
	}
	return computer, user, strings.TrimSpace(windows)
}

// Build returns the build of Windows with its update number, such as
// 19045.5247. The last part goes up with each monthly update.
func Build() string {
	const current = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	build, _ := reg.Text(reg.Machine, current, reg.Native, "CurrentBuild")
	if update, ok := reg.Number(reg.Machine, current, reg.Native, "UBR"); ok {
		build += "." + strconv.Itoa(int(update))
	}
	return build
}

var (
	accounts     = map[string]string{}
	accountsLock sync.Mutex
)

// AccountName turns the number Windows knows an account by (a SID, such as
// S-1-5-18) into its name. It returns the SID itself when Windows has no
// name for it.
func AccountName(sid string) string {
	sid = strings.TrimSpace(sid)
	if !strings.HasPrefix(strings.ToUpper(sid), "S-1-") {
		return sid
	}
	accountsLock.Lock()
	defer accountsLock.Unlock()
	if name, ok := accounts[sid]; ok {
		return name
	}
	name := sid
	if parsed, err := syscall.StringToSid(sid); err == nil {
		name = SIDName(parsed)
	}
	accounts[sid] = name
	return name
}

// SIDName returns the name of the account a SID stands for.
func SIDName(sid *syscall.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		if text, err := sid.String(); err == nil {
			return text
		}
		return ""
	}
	computer, _ := os.Hostname()
	switch {
	case domain == "", strings.EqualFold(domain, computer),
		strings.EqualFold(domain, "NT AUTHORITY"), strings.EqualFold(domain, "BUILTIN"):
		return account
	}
	return domain + `\` + account
}
