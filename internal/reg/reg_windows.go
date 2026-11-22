//go:build windows

// Package reg reads the registry, the database where Windows and its
// programs keep their settings. It only reads: nothing in this package can
// write to or delete from the registry.
package reg

import (
	"encoding/binary"
	"errors"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"lazascope/internal/sysdll"
)

var enumValue = sysdll.Load("advapi32.dll").NewProc("RegEnumValueW")

// The parts of the registry that are read from.
const (
	Machine = syscall.HKEY_LOCAL_MACHINE // settings for the whole PC
	User    = syscall.HKEY_CURRENT_USER  // settings for the account in use
	Classes = syscall.HKEY_CLASSES_ROOT  // what Windows knows about file types and program parts
)

// View chooses between the two sets of settings 64-bit Windows keeps side
// by side: one for 64-bit programs and one for 32-bit ones.
type View uint32

const (
	Native View = 0x0100 // as 64-bit programs see the registry
	Compat View = 0x0200 // as 32-bit programs see it
)

// The kinds of value.
const (
	KindText       = 1 // text
	KindExpandable = 2 // text with names such as %SystemRoot% to fill in
	KindBinary     = 3 // raw bytes
	KindNumber     = 4 // a 32-bit number
	KindList       = 7 // several pieces of text
	KindBigNumber  = 11
)

// Key is one open key, a folder of the registry.
type Key struct{ handle syscall.Handle }

// Open opens a key for reading only.
func Open(root syscall.Handle, path string, view View) (*Key, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const read = 0x20019 // KEY_READ: look at values and subkeys, nothing more
	var handle syscall.Handle
	if err := syscall.RegOpenKeyEx(root, name, 0, read|uint32(view), &handle); err != nil {
		return nil, err
	}
	return &Key{handle}, nil
}

// Refused reports whether opening a key failed because this account may not
// read it, which usually means it needs administrator rights.
func Refused(err error) bool { return errors.Is(err, syscall.ERROR_ACCESS_DENIED) }

// Close lets go of the key.
func (k *Key) Close() {
	if k != nil {
		syscall.RegCloseKey(k.handle)
	}
}

// Sub opens a key inside this one.
func (k *Key) Sub(path string) (*Key, error) { return Open(k.handle, path, 0) }

// raw reads a value's bytes and its kind.
func (k *Key) raw(name string) (data []byte, kind uint32, ok bool) {
	wide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, 0, false
	}
	size := uint32(512)
	for range 4 {
		data = make([]byte, size)
		err = syscall.RegQueryValueEx(k.handle, wide, nil, &kind, &data[0], &size)
		if err == nil {
			return data[:size], kind, true
		}
		if err != syscall.ERROR_MORE_DATA {
			return nil, 0, false
		}
		size += 2
	}
	return nil, 0, false
}

// text turns the bytes of a text value into text.
func text(data []byte) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	for i, unit := range units {
		if unit == 0 {
			units = units[:i]
			break
		}
	}
	return string(utf16.Decode(units))
}

// list turns the bytes of a list value into its pieces.
func list(data []byte) []string {
	var pieces []string
	var units []uint16
	for i := 0; i+1 < len(data); i += 2 {
		unit := binary.LittleEndian.Uint16(data[i:])
		if unit != 0 {
			units = append(units, unit)
			continue
		}
		if len(units) > 0 {
			pieces = append(pieces, string(utf16.Decode(units)))
			units = nil
		}
	}
	if len(units) > 0 {
		pieces = append(pieces, string(utf16.Decode(units)))
	}
	return pieces
}

// Text returns a text value. The value with the empty name is the one
// Registry Editor shows as (Default).
func (k *Key) Text(name string) (string, bool) {
	data, kind, ok := k.raw(name)
	if !ok || (kind != KindText && kind != KindExpandable) {
		return "", false
	}
	return text(data), true
}

// Number returns a number value.
func (k *Key) Number(name string) (uint32, bool) {
	data, kind, ok := k.raw(name)
	if !ok || kind != KindNumber || len(data) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data), true
}

// List returns a value made of several pieces of text.
func (k *Key) List(name string) ([]string, bool) {
	data, kind, ok := k.raw(name)
	if !ok || kind != KindList {
		return nil, false
	}
	return list(data), true
}

// Bytes returns a value as it is stored.
func (k *Key) Bytes(name string) ([]byte, bool) {
	data, _, ok := k.raw(name)
	return data, ok
}

// Value is one named value of a key.
type Value struct {
	Name string
	Kind uint32
	Text string // for text values, the text; for a list, its pieces joined with spaces
	Data []byte
}

// Number returns the value as a number, when it is one.
func (v Value) Number() (uint32, bool) {
	if v.Kind != KindNumber || len(v.Data) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v.Data), true
}

// counts asks how many subkeys and values a key has, how long the longest
// names and the largest value are, and when the key was last written.
func (k *Key) counts() (subkeys, longestSubkey, values, longestName, largest uint32, written time.Time) {
	var stamp syscall.Filetime
	syscall.RegQueryInfoKey(k.handle, nil, nil, nil, &subkeys, &longestSubkey, nil, &values, &longestName, &largest, nil, &stamp)
	if stamp.HighDateTime != 0 || stamp.LowDateTime != 0 {
		written = time.Unix(0, stamp.Nanoseconds())
	}
	return
}

// Written returns when the key was last changed.
func (k *Key) Written() time.Time {
	_, _, _, _, _, written := k.counts()
	return written
}

// Values returns every value of the key.
func (k *Key) Values() []Value {
	_, _, count, longestName, largest, _ := k.counts()
	var values []Value
	name := make([]uint16, longestName+2)
	data := make([]byte, largest+4)
	for i := uint32(0); i < count+16; i++ {
		nameLength, size, kind := uint32(len(name)), uint32(len(data)), uint32(0)
		r, _, _ := enumValue.Call(uintptr(k.handle), uintptr(i), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLength)),
			0, uintptr(unsafe.Pointer(&kind)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)))
		if syscall.Errno(r) == syscall.ERROR_MORE_DATA {
			// The key grew since it was measured. Make room and ask again.
			name, data = make([]uint16, 2*len(name)+64), make([]byte, 2*len(data)+1024)
			i--
			if len(data) > 1<<24 {
				break
			}
			continue
		}
		if r != 0 {
			break // no more values
		}
		value := Value{Name: syscall.UTF16ToString(name[:nameLength]), Kind: kind, Data: append([]byte(nil), data[:size]...)}
		switch kind {
		case KindText, KindExpandable:
			value.Text = text(value.Data)
		case KindList:
			pieces := list(value.Data)
			for j, piece := range pieces {
				if j > 0 {
					value.Text += " "
				}
				value.Text += piece
			}
		}
		values = append(values, value)
	}
	return values
}

// Subkeys returns the names of the keys inside this one.
func (k *Key) Subkeys() []string {
	count, longest, _, _, _, _ := k.counts()
	names := make([]string, 0, count)
	buffer := make([]uint16, max(longest+2, 256))
	for i := uint32(0); ; i++ {
		length := uint32(len(buffer))
		err := syscall.RegEnumKeyEx(k.handle, i, &buffer[0], &length, nil, nil, nil, nil)
		if err == syscall.ERROR_MORE_DATA {
			buffer = make([]uint16, 2*len(buffer))
			i--
			if len(buffer) > 1<<16 {
				break
			}
			continue
		}
		if err != nil {
			break
		}
		names = append(names, syscall.UTF16ToString(buffer[:length]))
	}
	return names
}

// Text reads one text value without keeping the key open.
func Text(root syscall.Handle, path string, view View, name string) (string, bool) {
	key, err := Open(root, path, view)
	if err != nil {
		return "", false
	}
	defer key.Close()
	return key.Text(name)
}

// Number reads one number value without keeping the key open.
func Number(root syscall.Handle, path string, view View, name string) (uint32, bool) {
	key, err := Open(root, path, view)
	if err != nil {
		return 0, false
	}
	defer key.Close()
	return key.Number(name)
}
