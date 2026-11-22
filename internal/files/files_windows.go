//go:build windows

// Package files looks up the facts about a program file: whether it
// exists, what it says of itself, and who signed it. Each file is looked at
// once however many start-up entries and running programs name it.
package files

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"lazascope/internal/model"
	"lazascope/internal/sigcheck"
	"lazascope/internal/sysdll"
)

var (
	version      = sysdll.Load("version.dll")
	detailsSize  = version.NewProc("GetFileVersionInfoSizeW")
	detailsRead  = version.NewProc("GetFileVersionInfoW")
	detailsQuery = version.NewProc("VerQueryValueW")
)

// Library remembers what it has found out about each file.
type Library struct {
	checker *sigcheck.Checker
	lock    sync.Mutex
	seen    map[string]*known
}

type known struct {
	once sync.Once
	file model.File
}

// Open returns an empty Library. Close it when done.
func Open() *Library {
	return &Library{checker: sigcheck.New(), seen: map[string]*known{}}
}

// Close gives back what the Library holds of Windows.
func (l *Library) Close() { l.checker.Close() }

// Count returns how many different files have been looked at.
func (l *Library) Count() int {
	l.lock.Lock()
	defer l.lock.Unlock()
	return len(l.seen)
}

// Look returns the facts about a file. It is safe to call from several
// goroutines at once. An empty path gives an empty answer.
func (l *Library) Look(path string) model.File {
	if path == "" {
		return model.File{}
	}
	key := strings.ToLower(path)
	l.lock.Lock()
	entry := l.seen[key]
	if entry == nil {
		entry = &known{}
		l.seen[key] = entry
	}
	l.lock.Unlock()
	entry.once.Do(func() { entry.file = l.look(path) })
	return entry.file
}

func (l *Library) look(path string) (file model.File) {
	file = model.File{Path: path}
	// One odd file must not end the whole look. If reading it goes wrong
	// inside LazaScope, what was learnt up to then is kept and the file says
	// that it could not be checked.
	defer func() {
		if fault := recover(); fault != nil && file.Signature.Status == sigcheck.Unknown {
			file.Signature.Problem = fmt.Sprintf("LazaScope could not finish looking at this file, because of an error of its own (%v).", fault)
		}
	}()
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		file.Signature = l.checker.Check(path) // for its wording of why not
		return file
	}
	file.Exists, file.Size, file.Modified = true, info.Size(), info.ModTime()
	file.Program = program(path)
	if !file.Program {
		// A script or a document has no maker's seal worth reporting, and
		// asking Windows to check one says "not signed" for nearly all.
		return file
	}
	file.Signature = l.checker.Check(path)
	file.Company, file.Description, file.Product, file.Version, file.Original = Describe(path)
	return file
}

// program reports whether a file is a Windows program or library. Every
// one of those starts with the letters MZ, whatever its name ends in.
func program(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var start [2]byte
	if _, err := f.Read(start[:]); err != nil {
		return false
	}
	return start[0] == 'M' && start[1] == 'Z'
}

// Describe returns what a program file says about itself in the details
// that Explorer shows under Properties. Anyone can write anything there, so
// this is a claim and not proof of who made the file.
func Describe(path string) (company, description, product, number, original string) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	var unused uint32
	size, _, _ := detailsSize.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&unused)))
	if size == 0 || size > 16<<20 {
		return
	}
	data := make([]byte, size+8)
	if ok, _, _ := detailsRead.Call(uintptr(unsafe.Pointer(name)), 0, size, uintptr(unsafe.Pointer(&data[0]))); ok == 0 {
		return
	}
	// query returns the part of data that a named entry occupies.
	query := func(entry string, unit int) []byte {
		wide, err := syscall.UTF16PtrFromString(entry)
		if err != nil {
			return nil
		}
		var at unsafe.Pointer
		var length uint32
		if ok, _, _ := detailsQuery.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(wide)), uintptr(unsafe.Pointer(&at)), uintptr(unsafe.Pointer(&length))); ok == 0 || at == nil {
			return nil
		}
		start := uintptr(at) - uintptr(unsafe.Pointer(&data[0]))
		end := start + uintptr(length)*uintptr(unit)
		if start > uintptr(len(data)) || end > uintptr(len(data)) {
			return nil
		}
		return data[start:end]
	}
	// The details are stored once per language. Take the languages the file
	// lists, then the common ones in case its list is wrong.
	var languages []string
	if table := query(`\VarFileInfo\Translation`, 1); len(table) >= 4 {
		for i := 0; i+4 <= len(table); i += 4 {
			languages = append(languages, fmt.Sprintf("%04x%04x", binary.LittleEndian.Uint16(table[i:]), binary.LittleEndian.Uint16(table[i+2:])))
		}
	}
	languages = append(languages, "040904b0", "040904e4", "04090000", "000004b0")
	read := func(field string) string {
		for _, language := range languages {
			raw := query(`\StringFileInfo\`+language+`\`+field, 2)
			if len(raw) < 2 {
				continue
			}
			units := make([]uint16, len(raw)/2)
			for i := range units {
				units[i] = binary.LittleEndian.Uint16(raw[2*i:])
			}
			if text := strings.TrimSpace(syscall.UTF16ToString(units)); text != "" {
				return text
			}
		}
		return ""
	}
	return read("CompanyName"), read("FileDescription"), read("ProductName"), read("FileVersion"), read("OriginalFilename")
}
