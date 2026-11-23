// Package health reads what Windows has written in its own log about the
// PC's hardware and about itself stopping, and how full the disks are.
//
// A PC that keeps crashing for no clear reason is often not infected but
// worn: a processor, a memory module or a disk that has started to fail.
// Windows notes each such error as it happens, in a log few people open.
package health

import (
	"strconv"
	"strings"

	"lazascope/internal/eventlog"
	"lazascope/internal/model"
)

// Days is how far back the look goes.
const Days = 90

// The parts of Windows that write the records read here.
const (
	hardwareWriter = "Microsoft-Windows-WHEA-Logger"
	crashWriter    = "Microsoft-Windows-WER-SystemErrorReporting"
	powerWriter    = "Microsoft-Windows-Kernel-Power"
	diskWriter     = "disk"
	logWriter      = "Microsoft-Windows-Eventlog"
)

// The stop codes met most often, by name. Windows shows the name on the
// blue screen itself.
var stopCodes = map[uint32]string{
	0x01: "APC_INDEX_MISMATCH", 0x0A: "IRQL_NOT_LESS_OR_EQUAL", 0x18: "REFERENCE_BY_POINTER", 0x19: "BAD_POOL_HEADER", 0x1A: "MEMORY_MANAGEMENT",
	0x1E: "KMODE_EXCEPTION_NOT_HANDLED", 0x24: "NTFS_FILE_SYSTEM", 0x3B: "SYSTEM_SERVICE_EXCEPTION", 0x4E: "PFN_LIST_CORRUPT",
	0x50: "PAGE_FAULT_IN_NONPAGED_AREA", 0x7A: "KERNEL_DATA_INPAGE_ERROR", 0x7B: "INACCESSIBLE_BOOT_DEVICE",
	0x7E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", 0x7F: "UNEXPECTED_KERNEL_MODE_TRAP", 0x9F: "DRIVER_POWER_STATE_FAILURE",
	0xA0: "INTERNAL_POWER_ERROR", 0xBE: "ATTEMPTED_WRITE_TO_READONLY_MEMORY", 0xC2: "BAD_POOL_CALLER",
	0xC4: "DRIVER_VERIFIER_DETECTED_VIOLATION", 0xC5: "DRIVER_CORRUPTED_EXPOOL", 0xD1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
	0xEF: "CRITICAL_PROCESS_DIED", 0xF4: "CRITICAL_OBJECT_TERMINATION", 0xFC: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
	0x101: "CLOCK_WATCHDOG_TIMEOUT", 0x109: "CRITICAL_STRUCTURE_CORRUPTION", 0x10D: "WDF_VIOLATION",
	0x113: "VIDEO_DXGKRNL_FATAL_ERROR", 0x116: "VIDEO_TDR_FAILURE", 0x119: "VIDEO_SCHEDULER_INTERNAL_ERROR",
	0x124: "WHEA_UNCORRECTABLE_ERROR", 0x133: "DPC_WATCHDOG_VIOLATION", 0x139: "KERNEL_SECURITY_CHECK_FAILURE",
	0x13A: "KERNEL_MODE_HEAP_CORRUPTION", 0x154: "UNEXPECTED_STORE_EXCEPTION", 0x1CA: "SYNTHETIC_WATCHDOG_TIMEOUT",
	0x20001: "HYPERVISOR_ERROR", 0x1000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M", 0x1000008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M",
	0xC000021A: "WINLOGON_FATAL_ERROR",
}

// StopCode names a stop code, or returns "" for one not in the list.
func StopCode(code uint32) string { return stopCodes[code] }

// Line puts a record's message on one line. Windows writes it as several
// short lines, the last of which only points at Event Viewer.
func Line(message string) string {
	var parts []string
	for _, line := range strings.Split(message, "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line == "" || strings.HasPrefix(line, "The details view of this entry") {
			continue
		}
		if last := line[len(line)-1]; last != '.' && last != ':' && last != '!' && last != '?' {
			line += "."
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, " ")
}

// Hardware turns a record of a hardware error into a fault.
func Hardware(e eventlog.Event) model.Fault {
	fault := model.Fault{When: e.Time, ID: e.ID, Fatal: e.Level != 0 && e.Level <= eventlog.Error, Words: Line(e.Message), Part: "a part of the hardware"}
	_, bus := e.Data["PrimaryBusNumber"]
	_, address := e.Data["PhysicalAddress"]
	switch {
	case e.Value("ApicId") != "":
		fault.Part = "the processor"
		fault.Where = "APIC ID " + e.Value("ApicId")
	case e.ID == 46 || e.ID == 47 || address:
		fault.Part = "the memory"
	case e.ID == 17 || bus:
		fault.Part = "a part on the PCI Express bus, such as a graphics card, an SSD or a network card"
	}
	if fault.Words == "" {
		fault.Words = "A hardware error (record number " + strconv.Itoa(e.ID) + " of WHEA-Logger)."
		if !fault.Fatal {
			fault.Words = "A corrected hardware error (record number " + strconv.Itoa(e.ID) + " of WHEA-Logger)."
		}
	}
	return fault
}

// Crash turns the record Windows writes after a blue screen into a crash.
// The record gives the stop code and its four values as one piece of text,
// such as "0x00000050 (0xffff8b8b790ef188, 0x11, ...)".
func Crash(e eventlog.Event) (model.Crash, bool) {
	text := e.Value("param1")
	if text == "" && len(e.Loose) > 0 {
		text = e.Loose[0]
	}
	word := text
	if cut := strings.IndexAny(word, " ("); cut >= 0 {
		word = word[:cut]
	}
	word = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(word)), "0x")
	code, err := strconv.ParseUint(word, 16, 32)
	if err != nil || word == "" {
		return model.Crash{}, false
	}
	return model.Crash{When: e.Time, Code: uint32(code), Name: StopCode(uint32(code))}, true
}

// PowerCut reports whether a record of "restarted without shutting down"
// stands for the power going or the PC freezing, as opposed to a blue
// screen, which leaves its stop code in the same record.
func PowerCut(e eventlog.Event) bool {
	code, ok := e.Number("BugcheckCode")
	return !ok || code == 0
}

// The records the disk driver writes that mean the disk itself is at fault.
const (
	badBlock        = 7
	failurePredicts = 52
	corruptFiles    = 55 // written by the file system
)

// Disk turns a record about a disk into a fault. retry is true for the
// records that only say Windows had to ask twice, which a loose cable or a
// USB drive pulled out too early also cause.
func Disk(e eventlog.Event) (fault model.Fault, retry bool) {
	fault = model.Fault{When: e.Time, ID: e.ID, Part: "a disk", Words: Line(e.Message)}
	if len(e.Loose) > 0 {
		fault.Where = e.Loose[0]
	}
	switch e.ID {
	case badBlock:
		if fault.Words == "" {
			fault.Words = "A disk has a bad block: a spot it can no longer read."
		}
	case failurePredicts:
		fault.Fatal = true
		if fault.Words == "" {
			fault.Words = "A disk has reported that it expects to fail."
		}
	case corruptFiles:
		if fault.Words == "" {
			fault.Words = "The file system on a disk is damaged."
		}
	default:
		return fault, true
	}
	return fault, false
}

// Wipe turns the record of a log being cleared into a wipe.
func Wipe(e eventlog.Event, log string) model.Wipe {
	wiped := e.Value("Channel")
	if wiped == "" {
		wiped = log
	}
	return model.Wipe{When: e.Time, Log: wiped, By: e.Value("SubjectUserName")}
}
