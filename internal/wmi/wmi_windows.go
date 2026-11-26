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
	objectFace   = com.ID("{DC12A681-737F-11CF-884D-00AA004B2E24}") // IWbemClassObject
	setBlanket   = sysdll.Load("ole32.dll").NewProc("CoSetProxyBlanket")
	variantClear = sysdll.Load("oleaut32.dll").NewProc("VariantClear")
	stringLength = sysdll.Load("oleaut32.dll").NewProc("SysStringLen")
	arrayLower   = sysdll.Load("oleaut32.dll").NewProc("SafeArrayGetLBound")
	arrayUpper   = sysdll.Load("oleaut32.dll").NewProc("SafeArrayGetUBound")
	arrayElement = sysdll.Load("oleaut32.dll").NewProc("SafeArrayGetElement")
)

// The places in the tables of functions WMI's objects hand back.
const (
	connectServer = 3  // IWbemLocator::ConnectServer
	execQuery     = 20 // IWbemServices::ExecQuery
	execNotify    = 22 // IWbemServices::ExecNotificationQuery
	next          = 4  // IEnumWbemClassObject::Next
	get           = 4  // IWbemClassObject::Get
)

// ErrTimeout is returned when WMI does not answer in time.
var ErrTimeout = errors.New("WMI did not answer in time")

// Query runs a query in WQL, WMI's form of SQL, in a namespace, and returns
// the named properties of each object found, as whole numbers, lists of
// whole numbers, true or false, or text. It runs on a thread of its own and
// gives up after the time given.
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

// Watch asks WMI to report the events a query in WQL describes, and calls
// each with the named properties of the object each event is about (its
// TargetInstance), until stop is closed. It runs on a thread of its own and
// returns when stopped, or when WMI fails.
func Watch(namespace, wql string, properties []string, stop <-chan struct{}, each func(map[string]any)) error {
	failed := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		leave, err := com.Enter()
		if err != nil {
			failed <- err
			return
		}
		defer leave()
		failed <- watch(namespace, wql, properties, stop, each)
	}()
	return <-failed
}

func watch(namespace, wql string, properties []string, stop <-chan struct{}, each func(map[string]any)) error {
	locator, err := com.Create(locatorClass, locatorFace)
	if err != nil {
		return err
	}
	defer locator.Release()
	ns := com.String(namespace)
	defer com.Free(ns)
	var services unsafe.Pointer
	if r := locator.Call(connectServer, ns, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&services))); com.Failed(r) || services == nil {
		return fmt.Errorf("WMI did not open %s (0x%08X)", namespace, uint32(r))
	}
	svc := com.Wrap(services)
	defer svc.Release()
	setBlanket.Call(uintptr(services), 10, 0, 0, 3, 3, 0, 0)
	language, text := com.String("WQL"), com.String(wql)
	defer com.Free(language)
	defer com.Free(text)
	var enumerator unsafe.Pointer
	const forwardOnly, returnAtOnce = 0x20, 0x10
	if r := svc.Call(execNotify, language, text, forwardOnly|returnAtOnce, 0, uintptr(unsafe.Pointer(&enumerator))); com.Failed(r) || enumerator == nil {
		return fmt.Errorf("WMI refused to report the events (0x%08X)", uint32(r))
	}
	list := com.Wrap(enumerator)
	defer list.Release()
	target, _ := syscall.UTF16PtrFromString("TargetInstance")
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		var object unsafe.Pointer
		var returned uint32
		r := list.Call(next, 500, 1, uintptr(unsafe.Pointer(&object)), uintptr(unsafe.Pointer(&returned)))
		if returned == 0 || object == nil {
			if com.Failed(r) {
				return fmt.Errorf("WMI stopped reporting (0x%08X)", uint32(r))
			}
			continue // half a second with nothing to report
		}
		event := com.Wrap(object)
		row := map[string]any{}
		var v com.Variant
		if r := event.Call(get, uintptr(unsafe.Pointer(target)), 0, uintptr(unsafe.Pointer(&v)), 0, 0); !com.Failed(r) && v.Kind == 13 && v.Value != 0 {
			address := uintptr(v.Value)
			inner := com.Wrap(*(*unsafe.Pointer)(unsafe.Pointer(&address)))
			if item, err := inner.Ask(objectFace); err == nil {
				for _, name := range properties {
					wide, err := syscall.UTF16PtrFromString(name)
					if err != nil {
						continue
					}
					var p com.Variant
					if r := item.Call(get, uintptr(unsafe.Pointer(wide)), 0, uintptr(unsafe.Pointer(&p)), 0, 0); !com.Failed(r) {
						if value, ok := read(&p); ok {
							row[name] = value
						}
						variantClear.Call(uintptr(unsafe.Pointer(&p)))
					}
				}
				item.Release()
			}
		}
		variantClear.Call(uintptr(unsafe.Pointer(&v)))
		event.Release()
		each(row)
	}
}

// read takes the value out of a VARIANT, for the kinds WMI uses for
// numbers, lists of numbers, true or false, and text. VariantClear gives
// the memory back.
func read(v *com.Variant) (any, bool) {
	const list = 0x2000 // VT_ARRAY
	if v.Kind&list != 0 {
		return numbers(uintptr(v.Value), v.Kind&^list)
	}
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

// numbers reads a SAFEARRAY of whole numbers, the form WMI gives a list of
// numbers in, such as the protections Device Guard reports running. Lists
// of anything else are not read.
func numbers(array uintptr, kind uint16) ([]int64, bool) {
	switch kind {
	case 16, 17, 2, 18, 3, 19: // the kinds of whole number read above
	default:
		return nil, false
	}
	if array == 0 {
		return nil, false
	}
	var lower, upper int32
	if failed, _, _ := arrayLower.Call(array, 1, uintptr(unsafe.Pointer(&lower))); failed != 0 {
		return nil, false
	}
	if failed, _, _ := arrayUpper.Call(array, 1, uintptr(unsafe.Pointer(&upper))); failed != 0 {
		return nil, false
	}
	found := []int64{}
	for i := lower; i <= upper && len(found) < 1000; i++ {
		var element uint64 // room for the widest kind read
		index := i
		if failed, _, _ := arrayElement.Call(array, uintptr(unsafe.Pointer(&index)), uintptr(unsafe.Pointer(&element))); failed != 0 {
			return nil, false
		}
		value, _ := read(&com.Variant{Kind: kind, Value: element})
		found = append(found, value.(int64))
	}
	return found, true
}
