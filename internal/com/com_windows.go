//go:build windows

// Package com calls the parts of Windows that are offered as COM objects:
// Task Scheduler, shortcuts, Windows Security. COM is the way one Windows
// component hands another a set of functions to call. Each object is a
// table of functions, called here by their place in the table.
package com

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"lazascope/internal/sysdll"
)

var (
	ole32    = sysdll.Load("ole32.dll")
	oleaut32 = sysdll.Load("oleaut32.dll")

	initialise   = ole32.NewProc("CoInitializeEx")
	uninitialise = ole32.NewProc("CoUninitialize")
	create       = ole32.NewProc("CoCreateInstance")
	taskFree     = ole32.NewProc("CoTaskMemFree")
	allocString  = oleaut32.NewProc("SysAllocString")
	freeString   = oleaut32.NewProc("SysFreeString")
	stringLength = oleaut32.NewProc("SysStringLen")
)

// GUID is the 128-bit number that names a COM class or a set of functions.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// ID reads a GUID written the usual way, such as
// "0F87369F-A4E5-4CFC-BD3E-73E6154572DD". It is for the fixed names in the
// source, and gives a zero GUID for text of another form.
func ID(text string) GUID {
	var g GUID
	var b [8]byte
	var d2, d3, d4 uint16
	if text != "" && text[0] == '{' && len(text) > 2 {
		text = text[1 : len(text)-1]
	}
	if _, err := fmt.Sscanf(text, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
		&g.Data1, &d2, &d3, &d4, &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]); err != nil {
		return GUID{}
	}
	g.Data2, g.Data3 = d2, d3
	b[0], b[1] = byte(d4>>8), byte(d4)
	g.Data4 = b
	return g
}

// Enter makes COM usable on the calling goroutine and ties the goroutine to
// its thread, because COM belongs to a thread. Call leave when done.
func Enter() (leave func(), err error) {
	runtime.LockOSThread()
	const oneThread = 2          // COINIT_APARTMENTTHREADED, which the shell's objects need
	const otherMode = 0x80010106 // COM is already running on this thread in another mode
	r, _, _ := initialise.Call(0, oneThread)
	switch uint32(r) {
	case 0, 1:
		return func() { uninitialise.Call(); runtime.UnlockOSThread() }, nil
	case otherMode:
		return runtime.UnlockOSThread, nil
	}
	runtime.UnlockOSThread()
	return func() {}, fmt.Errorf("COM could not be started (0x%08X)", uint32(r))
}

// Object is a COM object: a table of functions and the data they work on.
type Object struct{ pointer unsafe.Pointer }

// Create makes an object of a class and asks it for one set of functions.
func Create(class, functions GUID) (*Object, error) {
	const inProcess, localServer = 0x1, 0x4
	var pointer unsafe.Pointer
	r, _, _ := create.Call(uintptr(unsafe.Pointer(&class)), 0, inProcess|localServer, uintptr(unsafe.Pointer(&functions)), uintptr(unsafe.Pointer(&pointer)))
	if r != 0 || pointer == nil {
		return nil, fmt.Errorf("Windows would not provide the component (0x%08X)", uint32(r))
	}
	return &Object{pointer}, nil
}

// Wrap makes an Object of a pointer another object handed back.
func Wrap(pointer unsafe.Pointer) *Object {
	if pointer == nil {
		return nil
	}
	return &Object{pointer}
}

// Call calls the function at a place in the object's table and returns its
// result, which is zero for success.
//
// Arguments are plain numbers. The directive below tells Go that some of
// them are addresses of Go variables, which it then keeps in place and
// alive until the call returns.
//
//go:uintptrescapes
func (o *Object) Call(method int, arguments ...uintptr) uintptr {
	table := *(**[64]uintptr)(o.pointer)
	all := make([]uintptr, 0, 8)
	all = append(all, uintptr(o.pointer))
	all = append(all, arguments...)
	r, _, _ := syscall.SyscallN(table[method], all...)
	return r
}

// Ask asks the object for another of its sets of functions.
func (o *Object) Ask(functions GUID) (*Object, error) {
	var pointer unsafe.Pointer
	if r := o.Call(0, uintptr(unsafe.Pointer(&functions)), uintptr(unsafe.Pointer(&pointer))); r != 0 || pointer == nil {
		return nil, fmt.Errorf("the component does not offer that (0x%08X)", uint32(r))
	}
	return &Object{pointer}, nil
}

// Release says the object is no longer needed.
func (o *Object) Release() {
	if o != nil && o.pointer != nil {
		o.Call(2)
		o.pointer = nil
	}
}

// Failed reports whether a result from Call is an error.
func Failed(result uintptr) bool { return int32(result) < 0 }

// Variant mirrors VARIANT, the box COM passes values of any kind in.
type Variant struct {
	Kind     uint16
	reserved [3]uint16
	Value    uint64
	more     uint64
}

// Number returns a Variant that holds a whole number.
func Number(n int32) Variant {
	const int32Kind = 3 // VT_I4
	return Variant{Kind: int32Kind, Value: uint64(uint32(n))}
}

// at reads an address Windows returned as the pointer it is.
func at(address uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&address)) }

// String makes the kind of text COM functions take. Free it afterwards.
func String(text string) uintptr {
	wide, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return 0
	}
	b, _, _ := allocString.Call(uintptr(unsafe.Pointer(wide)))
	return b
}

// Free gives back text made by String or returned by a COM function.
func Free(text uintptr) {
	if text != 0 {
		freeString.Call(text)
	}
}

// Text reads text a COM function returned, and gives it back to Windows.
func Text(text uintptr) string {
	if text == 0 {
		return ""
	}
	defer Free(text)
	n, _, _ := stringLength.Call(text)
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice((*uint16)(at(text)), n))
}

// TaskText reads text a shell function returned, which is handed back in a
// different way from Text.
func TaskText(text unsafe.Pointer) string {
	if text == nil {
		return ""
	}
	defer taskFree.Call(uintptr(text))
	units := (*[1 << 20]uint16)(text)
	n := 0
	for n < len(units) && units[n] != 0 {
		n++
	}
	return syscall.UTF16ToString(units[:n])
}
