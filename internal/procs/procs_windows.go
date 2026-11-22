//go:build windows

// Package procs lists the programs running on this PC: where each one is on
// disk, the command that started it, what started it, whose it is and when
// it began.
package procs

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"lazascope/internal/model"
	"lazascope/internal/pcinfo"
	"lazascope/internal/sysdll"
)

var (
	ntdll    = sysdll.Load("ntdll.dll")
	kernel32 = sysdll.Load("kernel32.dll")
	wtsapi32 = sysdll.Load("wtsapi32.dll")

	querySystem  = ntdll.NewProc("NtQuerySystemInformation")
	queryProcess = ntdll.NewProc("NtQueryInformationProcess")
	imagePath    = kernel32.NewProc("QueryFullProcessImageNameW")
	dosDevice    = kernel32.NewProc("QueryDosDeviceW")
	wtsProcesses = wtsapi32.NewProc("WTSEnumerateProcessesW")
	wtsFree      = wtsapi32.NewProc("WTSFreeMemory")
)

const (
	processList    = 5          // SystemProcessInformation: every process, in one answer
	processImage   = 88         // SystemProcessIdInformation: the program file of one process
	commandLine    = 60         // ProcessCommandLineInformation
	tooSmall       = 0xC0000004 // the buffer given was not large enough
	limitedQuery   = 0x1000     // PROCESS_QUERY_LIMITED_INFORMATION: the least a process can be asked
	windowsEpoch   = 116444736000000000
	idle, system   = 0, 4 // the two processes that are Windows itself
	recordAtLeast  = 136
	offsetThreads  = 4
	offsetCreated  = 32
	offsetNameSize = 56
	offsetNameAt   = 64
	offsetPID      = 80
	offsetParent   = 88
	offsetSession  = 100
)

// at reads an address Windows returned as the pointer it is.
func at(address uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&address)) }

// Collect lists the running programs. It only reads. Nothing is opened
// with more than the right to ask a process about itself.
func Collect() ([]model.Process, []model.Gap) {
	gap := func(what string) []model.Gap { return []model.Gap{{Area: model.RunningNow, What: what}} }
	buffer, err := snapshot()
	if err != nil {
		return nil, gap("The list of running programs could not be read: " + err.Error() + ".")
	}
	var list []model.Process
	base := uintptr(unsafe.Pointer(&buffer[0]))
	le := binary.LittleEndian
	for offset := 0; offset+recordAtLeast <= len(buffer); {
		record := buffer[offset:]
		p := model.Process{
			PID:     uint32(le.Uint64(record[offsetPID:])),
			Parent:  uint32(le.Uint64(record[offsetParent:])),
			Session: le.Uint32(record[offsetSession:]),
		}
		if created := int64(le.Uint64(record[offsetCreated:])); created > windowsEpoch {
			p.Started = time.Unix(0, (created-windowsEpoch)*100)
		}
		// The name lies elsewhere in the same buffer.
		if start, size := uintptr(le.Uint64(record[offsetNameAt:]))-base, uintptr(le.Uint16(record[offsetNameSize:])); start < uintptr(len(buffer)) && start+size <= uintptr(len(buffer)) {
			units := make([]uint16, size/2)
			for i := range units {
				units[i] = le.Uint16(buffer[start+uintptr(2*i):])
			}
			p.Name = syscall.UTF16ToString(units)
		}
		switch p.PID {
		case idle:
			p.Name = "" // not a program: the time the processor spends doing nothing
		case system:
			p.Name = "System"
		}
		if p.Name != "" {
			list = append(list, p)
		}
		next := int(le.Uint32(record))
		if next == 0 {
			break
		}
		offset += next
	}

	drives := driveNames()
	names := map[string]string{} // account names already looked up
	pathless, commandless := 0, 0
	for i := range list {
		p := &list[i]
		if p.PID == system {
			p.User = "SYSTEM"
			continue
		}
		handle, err := syscall.OpenProcess(limitedQuery, false, p.PID)
		if err == nil {
			p.File.Path = pathOf(handle)
			p.Command, p.CommandHidden = commandOf(handle)
			p.User = ownerOf(handle, names)
			syscall.CloseHandle(handle)
		} else {
			p.CommandHidden = true
		}
		if p.File.Path == "" {
			// Windows will say where the program is even when the process
			// itself cannot be asked.
			p.File.Path = toDrivePath(imageOf(p.PID), drives)
		}
		if p.File.Path == "" && !partOfWindows(p.Name) {
			pathless++
		}
		if p.CommandHidden && !partOfWindows(p.Name) {
			commandless++
		}
	}
	// Terminal Services knows the owner of every process, also of those
	// that cannot be opened.
	for pid, owner := range owners(names) {
		for i := range list {
			if list[i].PID == pid && list[i].User == "" {
				list[i].User = owner
			}
		}
	}
	// A process keeps the number of the one that started it, but numbers
	// are handed out again. If the "parent" began later than the child, it
	// is a different program that got the old number.
	began := map[uint32]time.Time{}
	for _, p := range list {
		began[p.PID] = p.Started
	}
	for i := range list {
		p := &list[i]
		parent, running := began[p.Parent]
		if p.Parent == 0 || !running || (!parent.IsZero() && !p.Started.IsZero() && parent.After(p.Started)) {
			p.ParentGone = p.Parent != 0
		}
	}
	var gaps []model.Gap
	if pathless > 0 {
		gaps = append(gaps, gap(fmt.Sprintf("Windows would not say where %d running programs are on disk.", pathless))...)
	}
	if commandless > 0 {
		gaps = append(gaps, gap(fmt.Sprintf("The command lines of %d programs that run as other accounts can only be read with administrator rights.", commandless))...)
	}
	return list, gaps
}

// partOfWindows reports whether a process is one of the few that are
// Windows itself and have no program file or command line to show.
func partOfWindows(name string) bool {
	switch strings.ToLower(name) {
	case "system", "registry", "memory compression", "secure system", "vmmem", "vmmemwsl", "vmmemcmzygote":
		return true
	}
	return false
}

// snapshot asks Windows for every process at once.
func snapshot() ([]byte, error) {
	size := uint32(1 << 20)
	for range 8 {
		buffer := make([]byte, size)
		var needed uint32
		status, _, _ := querySystem.Call(processList, uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&needed)))
		if status == 0 {
			return buffer, nil
		}
		if uint32(status) != tooSmall {
			return nil, fmt.Errorf("Windows answered 0x%08X", uint32(status))
		}
		size = max(size, needed) + 256<<10
	}
	return nil, fmt.Errorf("the list kept growing")
}

// pathOf returns where a process's program is on disk.
func pathOf(handle syscall.Handle) string {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if ok, _, _ := imagePath.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size))); ok == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer[:size])
}

// commandOf returns the command a process was started with. hidden is true
// when Windows refused to give it.
func commandOf(handle syscall.Handle) (command string, hidden bool) {
	buffer := make([]byte, 66000)
	var size uint32
	status, _, _ := queryProcess.Call(uintptr(handle), commandLine, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&size)))
	if status != 0 {
		return "", true
	}
	// The answer is a length, then the address of the text, which lies in
	// the same buffer.
	length := uintptr(binary.LittleEndian.Uint16(buffer))
	start := uintptr(binary.LittleEndian.Uint64(buffer[8:])) - uintptr(unsafe.Pointer(&buffer[0]))
	if start >= uintptr(len(buffer)) || start+length > uintptr(len(buffer)) {
		return "", false
	}
	units := make([]uint16, length/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(buffer[start+uintptr(2*i):])
	}
	return syscall.UTF16ToString(units), false
}

// ownerOf returns the account a process runs as.
func ownerOf(handle syscall.Handle, names map[string]string) string {
	var token syscall.Token
	if err := syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	return name(user.User.Sid, names)
}

// name looks an account's name up once and remembers it.
func name(sid *syscall.SID, names map[string]string) string {
	key, err := sid.String()
	if err != nil {
		return ""
	}
	if known, ok := names[key]; ok {
		return known
	}
	names[key] = pcinfo.SIDName(sid)
	return names[key]
}

// imageOf asks Windows for the program file of a process by its number
// alone. The answer names the disk the way Windows does inside, such as
// \Device\HarddiskVolume3\Windows\System32\svchost.exe.
func imageOf(pid uint32) string {
	buffer := make([]uint16, 32767)
	request := struct {
		PID             uintptr
		Length, Maximum uint16
		Buffer          *uint16
	}{PID: uintptr(pid), Maximum: uint16(2 * len(buffer)), Buffer: &buffer[0]}
	if status, _, _ := querySystem.Call(processImage, uintptr(unsafe.Pointer(&request)), unsafe.Sizeof(request), 0); status != 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer[:request.Length/2])
}

// driveNames returns the inside name of each drive letter, so that
// \Device\HarddiskVolume3 can be turned back into C:.
func driveNames() map[string]string {
	names := map[string]string{}
	buffer := make([]uint16, 1024)
	for letter := 'A'; letter <= 'Z'; letter++ {
		drive := string(letter) + ":"
		wide, _ := syscall.UTF16PtrFromString(drive)
		if n, _, _ := dosDevice.Call(uintptr(unsafe.Pointer(wide)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))); n == 0 {
			continue
		}
		if device := syscall.UTF16ToString(buffer); device != "" {
			names[strings.ToLower(device)] = drive
		}
	}
	return names
}

// toDrivePath turns the inside form of a path into the usual one.
func toDrivePath(path string, drives map[string]string) string {
	lower := strings.ToLower(path)
	for device, drive := range drives {
		if strings.HasPrefix(lower, device+`\`) {
			return drive + path[len(device):]
		}
	}
	if strings.HasPrefix(lower, `\device\mup\`) {
		return `\\` + path[len(`\device\mup\`):] // a file on a network share
	}
	return ""
}

// owners asks Terminal Services, the part of Windows that manages
// sessions, for the account behind every process.
func owners(names map[string]string) map[uint32]string {
	type record struct {
		Session, PID uint32
		Name         *uint16
		SID          *syscall.SID
	}
	var list uintptr
	var count uint32
	if ok, _, _ := wtsProcesses.Call(0, 0, 1, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&count))); ok == 0 || list == 0 {
		return nil
	}
	defer wtsFree.Call(list)
	found := map[uint32]string{}
	for _, r := range unsafe.Slice((*record)(at(list)), count) {
		if r.SID != nil {
			if owner := name(r.SID, names); owner != "" {
				found[r.PID] = owner
			}
		}
	}
	return found
}
