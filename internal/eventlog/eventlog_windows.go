//go:build windows

package eventlog

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"lazascope/internal/sysdll"
)

var (
	wevtapi = sysdll.Load("wevtapi.dll")

	evtQuery    = wevtapi.NewProc("EvtQuery")
	evtNext     = wevtapi.NewProc("EvtNext")
	evtRender   = wevtapi.NewProc("EvtRender")
	evtClose    = wevtapi.NewProc("EvtClose")
	evtMetadata = wevtapi.NewProc("EvtOpenPublisherMetadata")
	evtFormat   = wevtapi.NewProc("EvtFormatMessage")
)

// ErrDenied is returned when this account may not read the log.
var ErrDenied = errors.New("Windows does not let this account read the log")

// ErrMissing is returned when the PC has no log of that name.
var ErrMissing = errors.New("this PC has no such log")

const (
	accessDenied       = 5
	insufficientBuffer = 122
	noMoreItems        = 259
	channelNotFound    = 15007
	timedOut           = 1460
)

// Read asks one of Windows' logs a question and returns the records that
// answer it, the newest first, and at most the given number. The log is
// opened for reading.
//
// log is the log's name, such as "System". question is written the way
// Event Viewer's own filters are; Where, From, Numbered and Since build one.
func Read(log, question string, most int) ([]Event, error) { return read(log, question, most, true) }

// ReadPlain is Read without Windows' own wording of each record, for
// records that are read for their values alone. It is a good deal quicker.
func ReadPlain(log, question string, most int) ([]Event, error) {
	return read(log, question, most, false)
}

func read(log, question string, most int, words bool) ([]Event, error) {
	if err := wevtapi.Load(); err != nil {
		return nil, err
	}
	name, err := syscall.UTF16PtrFromString(log)
	if err != nil {
		return nil, err
	}
	asked, err := syscall.UTF16PtrFromString(question)
	if err != nil {
		return nil, err
	}
	const byName, newestFirst = 0x1, 0x200
	results, _, failure := evtQuery.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(asked)), byName|newestFirst)
	if results == 0 {
		switch failure.(syscall.Errno) {
		case accessDenied:
			return nil, ErrDenied
		case channelNotFound:
			return nil, ErrMissing
		}
		return nil, fmt.Errorf("the log %s could not be opened: %v", log, failure)
	}
	defer evtClose.Call(results)

	var events []Event
	writers := map[string]uintptr{}
	defer func() {
		for _, writer := range writers {
			if writer != 0 {
				evtClose.Call(writer)
			}
		}
	}()
	var batch [16]uintptr
	for len(events) < most {
		var got uint32
		ok, _, failure := evtNext.Call(results, uintptr(len(batch)), uintptr(unsafe.Pointer(&batch[0])), 2000, 0, uintptr(unsafe.Pointer(&got)))
		if ok == 0 {
			if code := failure.(syscall.Errno); code != noMoreItems && code != timedOut {
				return events, fmt.Errorf("the log %s could not be read to its end: %v", log, failure)
			}
			break
		}
		for i := uint32(0); i < got; i++ {
			if len(events) < most {
				if event, err := Parse(render(batch[i])); err == nil {
					if words {
						event.Message = message(writers, event.Provider, batch[i])
					}
					events = append(events, event)
				}
			}
			evtClose.Call(batch[i])
		}
	}
	return events, nil
}

// render returns one record as the XML document Windows makes of it.
func render(record uintptr) string {
	const asXML = 1
	var used, properties uint32
	evtRender.Call(0, record, asXML, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if used == 0 || used > 4<<20 {
		return ""
	}
	buffer := make([]uint16, used/2+1)
	ok, _, _ := evtRender.Call(0, record, asXML, uintptr(len(buffer)*2), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}

// message returns a record in Windows' own words, or "" when Windows has
// none for it. The words come from files on this PC that belong to the part
// of Windows that wrote the record.
func message(writers map[string]uintptr, provider string, record uintptr) string {
	if provider == "" {
		return ""
	}
	writer, known := writers[provider]
	if !known {
		if name, err := syscall.UTF16PtrFromString(provider); err == nil {
			writer, _, _ = evtMetadata.Call(0, uintptr(unsafe.Pointer(name)), 0, 0, 0)
		}
		writers[provider] = writer
	}
	if writer == 0 {
		return ""
	}
	const theMessage = 1
	var used uint32
	evtFormat.Call(writer, record, 0, 0, 0, theMessage, 0, 0, uintptr(unsafe.Pointer(&used)))
	if used == 0 || used > 1<<20 {
		return ""
	}
	buffer := make([]uint16, used+1)
	ok, _, _ := evtFormat.Call(writer, record, 0, 0, 0, theMessage, uintptr(len(buffer)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&used)))
	if ok == 0 {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(syscall.UTF16ToString(buffer), "\r\n", "\n"))
}
