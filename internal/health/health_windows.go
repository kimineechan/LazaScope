//go:build windows

package health

import (
	"errors"
	"syscall"
	"time"
	"unsafe"

	"lazascope/internal/eventlog"
	"lazascope/internal/model"
	"lazascope/internal/sysdll"
)

var (
	kernel32 = sysdll.Load("kernel32.dll")

	logicalDrives = kernel32.NewProc("GetLogicalDrives")
	driveType     = kernel32.NewProc("GetDriveTypeW")
	freeSpace     = kernel32.NewProc("GetDiskFreeSpaceExW")
	tickCount     = kernel32.NewProc("GetTickCount64")
)

// most is how many records of one kind are read. A PC with more than this
// in ninety days has made its point.
const most = 500

// Collect reads the health of this PC. It only reads.
func Collect() (model.Condition, []model.Gap) {
	c := model.Condition{Days: Days}
	var gaps []model.Gap
	gap := func(what string) { gaps = append(gaps, model.Gap{Area: model.Health, What: what}) }

	hardware, err := eventlog.Read("System", eventlog.Where(eventlog.From(hardwareWriter), eventlog.Since(Days)), most)
	switch {
	case errors.Is(err, eventlog.ErrDenied):
		gap("Windows does not let this account read its log of hardware errors and crashes.")
	case err != nil:
		gap("Windows' log of hardware errors and crashes could not be read: " + err.Error() + ".")
	default:
		c.Read = true
	}
	for _, e := range hardware {
		c.Hardware = append(c.Hardware, Hardware(e))
	}
	if c.Read {
		crashes, _ := eventlog.Read("System", eventlog.Where(eventlog.From(crashWriter), eventlog.Numbered(1001), eventlog.Since(Days)), most)
		for _, e := range crashes {
			if crash, ok := Crash(e); ok {
				c.Crashes = append(c.Crashes, crash)
			}
		}
		cuts, _ := eventlog.Read("System", eventlog.Where(eventlog.From(powerWriter), eventlog.Numbered(41), eventlog.Since(Days)), most)
		for _, e := range cuts {
			if PowerCut(e) {
				c.PowerCuts = append(c.PowerCuts, e.Time)
			}
		}
		disk, _ := eventlog.Read("System", eventlog.Where(eventlog.From(diskWriter), eventlog.Numbered(badBlock, 11, 51, failurePredicts, 153), eventlog.Since(Days)), most)
		files, _ := eventlog.Read("System", "*[System[(Provider[@Name='Ntfs'] or Provider[@Name='Microsoft-Windows-Ntfs']) and EventID=55 and "+eventlog.Since(Days)+"]]", most)
		for _, e := range append(disk, files...) {
			if fault, retry := Disk(e); retry {
				c.Retries++
			} else {
				c.Disk = append(c.Disk, fault)
			}
		}
		wiped, _ := eventlog.Read("System", eventlog.Where(eventlog.From(logWriter), eventlog.Numbered(104), eventlog.Since(Days)), most)
		for _, e := range wiped {
			c.Wiped = append(c.Wiped, Wipe(e, "System"))
		}
		// The log of sign-ins and rights keeps its own note of being cleared.
		// Only an administrator may read that log, so without the rights this
		// simply finds nothing.
		if audit, err := eventlog.Read("Security", eventlog.Where(eventlog.Numbered(1102), eventlog.Since(Days)), most); err == nil {
			for _, e := range audit {
				c.Wiped = append(c.Wiped, Wipe(e, "Security"))
			}
		}
	}

	c.Drives = drives()
	if running, _, _ := tickCount.Call(); running != 0 {
		c.Started = time.Now().Add(-time.Duration(running) * time.Millisecond)
	}
	return c, gaps
}

// drives returns the PC's fixed disks and how full each is.
func drives() []model.Drive {
	present, _, _ := logicalDrives.Call()
	var found []model.Drive
	for i := 0; i < 26; i++ {
		if present&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A'+i)) + ":"
		root, err := syscall.UTF16PtrFromString(letter + `\`)
		if err != nil {
			continue
		}
		const fixed = 3
		if kind, _, _ := driveType.Call(uintptr(unsafe.Pointer(root))); kind != fixed {
			continue
		}
		var mine, size, free uint64
		if ok, _, _ := freeSpace.Call(uintptr(unsafe.Pointer(root)), uintptr(unsafe.Pointer(&mine)), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&free))); ok == 0 || size == 0 {
			continue
		}
		found = append(found, model.Drive{Letter: letter, Size: size, Free: free})
	}
	return found
}
