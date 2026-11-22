//go:build windows

// Package sysdll loads the parts of Windows this program calls, and only
// from Windows' own folder.
//
// A program that asks for "wintrust.dll" by name alone lets Windows look in
// several places, the program's own folder first. Someone who puts a file of
// that name beside the program gets their code run in its place. Asking for
// the full path closes that door, which matters for a tool people run from
// their Downloads folder.
package sysdll

import (
	"syscall"
	"unsafe"
)

var folder = func() string {
	// kernel32 is always in memory already, so asking for it by name is safe.
	get := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")
	buffer := make([]uint16, 300)
	n, _, _ := get.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || int(n) >= len(buffer) {
		return `C:\Windows\System32`
	}
	return syscall.UTF16ToString(buffer[:n])
}()

// Folder returns Windows' own folder for its program parts, usually
// C:\Windows\System32.
func Folder() string { return folder }

// Load prepares one of Windows' own DLLs, by its file name, for calling.
// Nothing is read from disk until the first call.
func Load(name string) *syscall.LazyDLL {
	return syscall.NewLazyDLL(folder + `\` + name)
}
