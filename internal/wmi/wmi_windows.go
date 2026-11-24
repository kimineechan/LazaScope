//go:build windows

// Package wmi asks Windows Management Instrumentation (WMI), the part of
// Windows that answers questions about the system, for a few values. It is
// how PowerShell's Get-MpPreference reads Microsoft Defender's settings,
// and LazaScope asks the same question the same way. It only reads.
package wmi

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"lazascope/internal/com"
	"lazascope/internal/sysdll"
)

var (
	locatorClass = com.ID("{4590F811-1D3A-11D0-891F-00AA004B2E24}") // WbemLocator
	locatorFace  = com.ID("{DC12A687-737F-11CF-884D-00AA004B2E24}") // IWbemLocator
	setBlanket   = sysdll.Load("ole32.dll").NewProc("CoSetProxyBlanket")
	variantClear = sysdll.Load("oleaut32.dll").NewProc("VariantClear")
	stringLength = sysdll.Load("oleaut32.dll").NewProc("SysStringLen")
)

// The places in the tables of functions WMI's objects hand back.
const (
	connectServer = 3  // IWbemLocator::ConnectServer
	execQuery     = 20 // IWbemServices::ExecQuery
	next          = 4  // IEnumWbemClassObject::Next
	get           = 4  // IWbemClassObject::Get
)

// ErrTimeout is returned when WMI does not answer in time.
var ErrTimeout = errors.New("WMI did not answer in time")

// Query runs a query in WQL, WMI's form of SQL, in a namespace, and returns
// the named properties of each object found, as whole numbers, true or
// false, or text. It runs on a thread of its own and gives up after the
// time given.
func Query(namespace, wql string, properties []string, wait time.Duration) ([]map[string]any, error) {
	type answer struct {
		rows []map[string]any
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		leave, err := com.Enter()
		if err != nil {
			done <- answer{nil, err}
			return
		}
		defer leave()
		rows, err := query(namespace, wql, properties)
		done <- answer{rows, err}
	}()
	select {
	case a := <-done:
		return a.rows, a.err
	case <-time.After(wait):
		return nil, ErrTimeout
	}
}

func query(namespace, wql string, properties []string) ([]map[string]any, error) {
	locator, err := com.Create(locatorClass, locatorFace)
	if err != nil {
		return nil, err
	}
	defer locator.Release()
	ns := com.String(namespace)
	defer com.Free(ns)
	var services unsafe.Pointer
	if r := locator.Call(connectServer, ns, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&services))); com.Failed(r) || services == nil {
		return nil, fmt.Errorf("WMI did not open %s (0x%08X)", namespace, uint32(r))
	}
	svc := com.Wrap(services)
	defer svc.Release()
	// Speak to WMI as this account, which is all reading needs: Windows'
	// own sign-in (RPC_C_AUTHN_WINNT), checked on every call
	// (RPC_C_AUTHN_LEVEL_CALL), acting as the caller (RPC_C_IMP_LEVEL_IMPERSONATE).
	setBlanket.Call(uintptr(services), 10, 0, 0, 3, 3, 0, 0)
	language, text := com.String("WQL"), com.String(wql)
	defer com.Free(language)
	defer com.Free(text)
	var enumerator unsafe.Pointer
	const forwardOnly, returnAtOnce = 0x20, 0x10
	if r := svc.Call(execQuery, language, text, forwardOnly|returnAtOnce, 0, uintptr(unsafe.Pointer(&enumerator))); com.Failed(r) || enumerator == nil {
		return nil, fmt.Errorf("WMI refused the question (0x%08X)", uint32(r))
	}
	list := com.Wrap(enumerator)
	defer list.Release()
	var rows []map[string]any
	for len(rows) < 1000 {
		var object unsafe.Pointer
		var returned uint32
		const infinite = 0xFFFFFFFF
		list.Call(next, infinite, 1, uintptr(unsafe.Pointer(&object)), uintptr(unsafe.Pointer(&returned)))
		if returned == 0 || object == nil {
			break
		}
		item := com.Wrap(object)
		row := map[string]any{}
		for _, name := range properties {
			wide, err := syscall.UTF16PtrFromString(name)
			if err != nil {
				continue
			}
			var v com.Variant
			if r := item.Call(get, uintptr(unsafe.Pointer(wide)), 0, uintptr(unsafe.Pointer(&v)), 0, 0); !com.Failed(r) {
				if value, ok := read(&v); ok {
					row[name] = value
				}
				variantClear.Call(uintptr(unsafe.Pointer(&v)))
			}
		}
		item.Release()
		rows = append(rows, row)
	}
	return rows, nil
}

// read takes the value out of a VARIANT, for the kinds WMI uses for
// numbers, true or false, and text. VariantClear gives the memory back.
func read(v *com.Variant) (any, bool) {
	switch v.Kind {
	case 16: // VT_I1
		return int64(int8(v.Value)), true
	case 17: // VT_UI1
		return int64(uint8(v.Value)), true
	case 2: // VT_I2
		return int64(int16(v.Value)), true
	case 18: // VT_UI2
		return int64(uint16(v.Value)), true
	case 3: // VT_I4
		return int64(int32(v.Value)), true
	case 19: // VT_UI4
		return int64(uint32(v.Value)), true
	case 11: // VT_BOOL
		return uint16(v.Value) != 0, true
	case 8: // VT_BSTR
		if v.Value == 0 {
			return "", true
		}
		address := uintptr(v.Value)
		n, _, _ := stringLength.Call(address)
		return syscall.UTF16ToString(unsafe.Slice((*uint16)(*(*unsafe.Pointer)(unsafe.Pointer(&address))), n)), true
	}
	return nil, false
}
