//go:build windows

// Package services asks Windows which services and drivers exist and
// which of them are running. A service is a background program that Windows
// starts itself; a driver is a part that runs inside Windows.
package services

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"lazascope/internal/reg"
	"lazascope/internal/sysdll"
)

var (
	advapi32    = sysdll.Load("advapi32.dll")
	openManager = advapi32.NewProc("OpenSCManagerW")
	enumerate   = advapi32.NewProc("EnumServicesStatusExW")
	closeHandle = advapi32.NewProc("CloseServiceHandle")
)

// State is one service or driver as it is now.
type State struct {
	Name    string // the short name Windows knows it by
	Title   string // the name shown in the Services window
	Driver  bool
	Running bool
	PID     uint32 // the program it runs inside, for a running service
}

// Account returns the account a service is set to run as.
func Account(name string) string {
	account, _ := reg.Text(reg.Machine, `SYSTEM\CurrentControlSet\Services\`+name, reg.Native, "ObjectName")
	return Plain(account)
}

// Plain puts the account a service runs as into plain words. Windows
// writes its three built-in service accounts in a form of its own.
func Plain(account string) string {
	switch strings.ToLower(account) {
	case "", "localsystem":
		return "SYSTEM"
	case `nt authority\localservice`:
		return "LOCAL SERVICE"
	case `nt authority\networkservice`:
		return "NETWORK SERVICE"
	}
	return account
}

// List returns every service and driver Windows knows of.
func List() ([]State, error) {
	// Only the right to connect and to list is asked for, which every
	// signed-in user has. Nothing can be started, stopped or changed with it.
	const connect, list = 0x0001, 0x0004
	manager, _, e := openManager.Call(0, 0, connect|list)
	if manager == 0 {
		return nil, fmt.Errorf("the list of services could not be opened: %w", e)
	}
	defer closeHandle.Call(manager)

	const (
		drivers, programs = 0x0B, 0x30 // SERVICE_DRIVER, SERVICE_WIN32
		everyState        = 3          // running or not
		running           = 4          // SERVICE_RUNNING
		moreData          = 234
		record            = 56 // the size of one ENUM_SERVICE_STATUS_PROCESSW
	)
	var needed, returned, resume uint32
	buffer := make([]byte, 256<<10)
	var states []State
	for range 64 {
		ok, _, e := enumerate.Call(manager, 0, drivers|programs, everyState, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)), uintptr(unsafe.Pointer(&resume)), 0)
		if ok == 0 && e != syscall.Errno(moreData) {
			return states, fmt.Errorf("the list of services could not be read: %w", e)
		}
		base := uintptr(unsafe.Pointer(&buffer[0]))
		// text reads a name that a record points to. The names lie in the
		// same buffer as the records.
		text := func(pointer uint64) string {
			start := uintptr(pointer) - base
			if pointer == 0 || start >= uintptr(len(buffer)) {
				return ""
			}
			var units []uint16
			for at := start; at+1 < uintptr(len(buffer)); at += 2 {
				unit := binary.LittleEndian.Uint16(buffer[at:])
				if unit == 0 {
					break
				}
				units = append(units, unit)
			}
			return syscall.UTF16ToString(units)
		}
		for i := 0; i < int(returned) && (i+1)*record <= len(buffer); i++ {
			entry := buffer[i*record:]
			kind := binary.LittleEndian.Uint32(entry[16:])
			states = append(states, State{
				Name:    text(binary.LittleEndian.Uint64(entry[0:])),
				Title:   text(binary.LittleEndian.Uint64(entry[8:])),
				Driver:  kind&drivers != 0,
				Running: binary.LittleEndian.Uint32(entry[20:]) == running,
				PID:     binary.LittleEndian.Uint32(entry[44:]),
			})
		}
		if ok != 0 {
			break // that was the last of them
		}
	}
	return states, nil
}
