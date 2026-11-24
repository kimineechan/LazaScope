//go:build windows

// Package clipboard runs the address-swap test. Some malware, called a
// clipper, watches the clipboard for a copied wallet address and puts its
// own in its place, so that coins sent to the pasted address go to a thief.
// The test copies made-up addresses, one at a time, and watches whether
// anything changes them. Afterwards it puts back the text that was on the
// clipboard before.
//
// The made-up addresses have the shape a clipper looks for and a checksum
// that is wrong on purpose, so no wallet would send coins to one even if
// it were pasted by mistake. They are marked so that Windows keeps them
// out of the clipboard history and does not send them to other devices.
package clipboard

import (
	"errors"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"lazascope/internal/model"
	"lazascope/internal/sysdll"
)

var (
	user32           = sysdll.Load("user32.dll")
	kernel32         = sysdll.Load("kernel32.dll")
	openClipboard    = user32.NewProc("OpenClipboard")
	closeClipboard   = user32.NewProc("CloseClipboard")
	emptyClipboard   = user32.NewProc("EmptyClipboard")
	getClipboardData = user32.NewProc("GetClipboardData")
	setClipboardData = user32.NewProc("SetClipboardData")
	clipboardOwner   = user32.NewProc("GetClipboardOwner")
	registerFormat   = user32.NewProc("RegisterClipboardFormatW")
	enumFormats      = user32.NewProc("EnumClipboardFormats")
	windowProcess    = user32.NewProc("GetWindowThreadProcessId")
	createWindow     = user32.NewProc("CreateWindowExW")
	peekMessage      = user32.NewProc("PeekMessageW")
	translateMessage = user32.NewProc("TranslateMessage")
	dispatchMessage  = user32.NewProc("DispatchMessageW")
	destroyWindow    = user32.NewProc("DestroyWindow")
	globalAlloc      = kernel32.NewProc("GlobalAlloc")
	globalLock       = kernel32.NewProc("GlobalLock")
	globalUnlock     = kernel32.NewProc("GlobalUnlock")
	globalFree       = kernel32.NewProc("GlobalFree")
	globalSize       = kernel32.NewProc("GlobalSize")
)

const unicodeText = 13 // CF_UNICODETEXT

// Address is a made-up wallet address of one kind.
type Address struct{ Kind, Text string }

// Addresses are the made-up addresses the test copies. Each fails its own
// checksum, which the tests prove: a Bitcoin address of the old kind whose
// checksum does not hold, a Bitcoin address of the new kind (bech32) whose
// checksum does not hold, and an Ethereum address whose mix of capital and
// small letters breaks its checksum (EIP-55).
var Addresses = []Address{
	{"Bitcoin", "1LazaScopeTestAddressDoNotUse"},
	{"Bitcoin (bc1)", "bc1q" + strings.Repeat("qpzry9x8gf", 3) + "2tvdw0s3"},
	{"Ethereum", "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"},
}

// ErrBusy is returned when another program keeps the clipboard open.
var ErrBusy = errors.New("another program is holding the clipboard open; try again in a moment")

// ErrNotRestored is returned when the clipboard could not be put back as
// it was before the test.
var ErrNotRestored = errors.New("the clipboard could not be put back as it was, because another program kept it busy; copy again whatever you need")

// pause waits, answering meanwhile the messages Windows sends to the
// windows of this thread. When another program empties the clipboard,
// Windows asks the clipboard's owner to let go, and waits until it has: a
// test that only slept would hold up every program that copies something.
func pause(d time.Duration) {
	var message [64]byte // a MSG, with room to spare
	for end := time.Now().Add(d); time.Now().Before(end); {
		for {
			got, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&message[0])), 0, 0, 0, 1) // PM_REMOVE
			if got == 0 {
				break
			}
			translateMessage.Call(uintptr(unsafe.Pointer(&message[0])))
			dispatchMessage.Call(uintptr(unsafe.Pointer(&message[0])))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// open opens the clipboard for a window, trying again for a short while
// when another program has it open. Windows ties the open clipboard to the
// thread that opened it, so every caller keeps to one thread, with
// runtime.LockOSThread, until it has closed the clipboard again.
func open(window uintptr) error {
	for range 20 {
		if ok, _, _ := openClipboard.Call(window); ok != 0 {
			return nil
		}
		pause(25 * time.Millisecond)
	}
	return ErrBusy
}

// Saved is what was on the clipboard before the test.
type Saved struct {
	Text     string
	HadText  bool
	HadOther bool // a picture or files, which the test cannot put back
}

// Look reads the text on the clipboard, and whether it also holds a
// picture or files.
func Look(window uintptr) (Saved, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var s Saved
	if err := open(window); err != nil {
		return s, err
	}
	defer closeClipboard.Call()
	for format := uintptr(0); ; {
		format, _, _ = enumFormats.Call(format)
		if format == 0 {
			break
		}
		switch format {
		case 2, 3, 8, 14, 15, 17: // bitmap, metafile, DIB, enhanced metafile, files, DIBV5
			s.HadOther = true
		}
	}
	s.Text, s.HadText = text()
	return s, nil
}

// text reads the clipboard's text. The clipboard must be open.
func text() (string, bool) {
	handle, _, _ := getClipboardData.Call(unicodeText)
	if handle == 0 {
		return "", false
	}
	locked, _, _ := globalLock.Call(handle)
	if locked == 0 {
		return "", false
	}
	defer globalUnlock.Call(handle)
	size, _, _ := globalSize.Call(handle)
	units := unsafe.Slice((*uint16)(pointer(&locked)), size/2)
	for i, u := range units {
		if u == 0 {
			units = units[:i]
			break
		}
	}
	return syscall.UTF16ToString(units), true
}

// put places text on the clipboard, marked to stay out of the clipboard
// history and off other devices.
func put(window uintptr, content string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := open(window); err != nil {
		return err
	}
	defer closeClipboard.Call()
	emptyClipboard.Call()
	units, err := syscall.UTF16FromString(content)
	if err != nil {
		return err
	}
	if err := place(unicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&units[0])), len(units)*2)); err != nil {
		return err
	}
	zero := []byte{0, 0, 0, 0}
	for _, name := range []string{"CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
		p, _ := syscall.UTF16PtrFromString(name)
		if format, _, _ := registerFormat.Call(uintptr(unsafe.Pointer(p))); format != 0 {
			place(format, zero)
		}
	}
	return nil
}

// place hands Windows a copy of data under a format. The clipboard must be open.
func place(format uintptr, data []byte) error {
	const moveable = 0x0002
	handle, _, _ := globalAlloc.Call(moveable, uintptr(len(data)))
	if handle == 0 {
		return errors.New("Windows had no memory to spare for the clipboard")
	}
	locked, _, _ := globalLock.Call(handle)
	if locked == 0 {
		globalFree.Call(handle)
		return errors.New("Windows had no memory to spare for the clipboard")
	}
	copy(unsafe.Slice((*byte)(pointer(&locked)), len(data)), data)
	globalUnlock.Call(handle)
	if ok, _, _ := setClipboardData.Call(format, handle); ok == 0 {
		globalFree.Call(handle) // Windows took nothing, so the memory is still ours
		return errors.New("Windows did not take the text onto the clipboard")
	}
	return nil
}

// Restore puts back what was on the clipboard before the test: its text,
// or nothing. While another program holds the clipboard, it keeps trying
// for a few seconds.
func Restore(window uintptr, s Saved) error {
	for end := time.Now().Add(5 * time.Second); ; {
		err := restore(window, s)
		if err == nil || time.Now().After(end) {
			return err
		}
		pause(100 * time.Millisecond)
	}
}

func restore(window uintptr, s Saved) error {
	if s.HadText {
		return put(window, s.Text)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := open(window); err != nil {
		return err
	}
	emptyClipboard.Call()
	closeClipboard.Call()
	return nil
}

// Test copies each made-up address, watches the clipboard for as long as
// wait says, and reports the first one a program swapped, with the program
// Windows says changed the clipboard, when it can say. The clipboard is put
// back as it was, as far as its text goes, before Test returns; when that
// fails, the result comes with ErrNotRestored.
//
// The window must answer its messages while the test runs: either its
// thread runs a message loop, as a program's main window does, or it was
// made by the goroutine that calls Test, on a thread locked to it, in which
// case Test answers them itself.
func Test(window uintptr, wait time.Duration) (result model.SwapTest, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result = model.SwapTest{When: time.Now()}
	saved, err := Look(window)
	if err != nil {
		return result, err
	}
	defer func() {
		if Restore(window, saved) != nil && err == nil {
			err = ErrNotRestored
		}
	}()
	for _, a := range Addresses {
		result.Tried = append(result.Tried, a.Kind)
		if err := put(window, a.Text); err != nil {
			return result, err
		}
		for deadline := time.Now().Add(wait); time.Now().Before(deadline); {
			pause(150 * time.Millisecond)
			now, owner, ok := peek(window)
			if !ok {
				continue // something else has the clipboard open; look again
			}
			if strings.TrimSpace(now) == a.Text {
				continue
			}
			result.Swapped, result.Kind = true, a.Kind
			result.Into = tidy(now)
			if owner != 0 && owner != window {
				var pid uint32
				windowProcess.Call(owner, uintptr(unsafe.Pointer(&pid)))
				result.PID = pid
			}
			return result, nil
		}
	}
	return result, nil
}

// pointer reads an address that Windows handed back as a number as the
// pointer it is. Windows owns the memory, so Go never moves it.
func pointer(address *uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(address)) }

// peek reads the clipboard's text and the window that last changed it.
func peek(window uintptr) (string, uintptr, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if open(window) != nil {
		return "", 0, false
	}
	defer closeClipboard.Call()
	now, _ := text()
	owner, _, _ := clipboardOwner.Call()
	return now, owner, true
}

// tidy keeps what a program put on the clipboard to one short line.
func tidy(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 120 {
		s = string(r[:119]) + "~"
	}
	return s
}

// Window makes an invisible window of the kind that only receives
// messages, for a program that has no window of its own to own the
// clipboard, and a function that removes it again.
func Window() (uintptr, func(), error) {
	class, _ := syscall.UTF16PtrFromString("STATIC")
	title, _ := syscall.UTF16PtrFromString("LazaScope address-swap test")
	const messageOnly = ^uintptr(2) // HWND_MESSAGE, which is -3
	window, _, err := createWindow.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), 0, 0, 0, 0, 0, messageOnly, 0, 0, 0)
	if window == 0 {
		return 0, func() {}, err
	}
	return window, func() { destroyWindow.Call(window) }, nil
}
