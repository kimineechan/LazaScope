//go:build windows

// Package amsi asks the antivirus installed on this PC what it makes of a
// piece of content: a script, or a command that was hidden in a start-up
// entry.
//
// Windows has a door for this, the Antimalware Scan Interface (AMSI). Any
// program may hand content through it, and whichever antivirus is
// installed answers: Microsoft Defender, or another maker's product if
// that is what the PC runs. LazaScope has no detection engine of its own
// and does not want one. This lets it say what the engine that is already
// there thinks, and name the antivirus as the one who said it.
//
// Nothing is run and nothing is changed. The content is read and shown to
// the antivirus, which may note what it found in its own log.
package amsi

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"lazascope/internal/com"
	"lazascope/internal/sysdll"
)

var (
	dll = sysdll.Load("amsi.dll")

	initialize   = dll.NewProc("AmsiInitialize")
	uninitialize = dll.NewProc("AmsiUninitialize")
	scanBuffer   = dll.NewProc("AmsiScanBuffer")
)

// Answer is what the antivirus said about a piece of content.
type Answer int

const (
	NotAsked    Answer = iota // nothing was handed over, or no antivirus answered
	NoObjection               // the antivirus looked and raised no objection
	Harmful                   // the antivirus calls it harmful
	Forbidden                 // a rule set by an administrator forbids it
)

func (a Answer) String() string {
	switch a {
	case NoObjection:
		return "no objection"
	case Harmful:
		return "harmful"
	case Forbidden:
		return "forbidden by a rule"
	}
	return "not asked"
}

// Most is the largest piece of content that is handed over.
const Most = 8 << 20

type question struct {
	content []byte
	name    string
	reply   chan reply
}

type reply struct {
	answer Answer
	err    error
}

// Asker holds the door open. It is safe to use from several goroutines.
type Asker struct {
	questions chan question
	done      chan struct{}
}

// Open opens the door for a program of the given name. The name is what
// the antivirus is told is asking.
func Open(app string) (*Asker, error) {
	if err := dll.Load(); err != nil {
		return nil, errors.New("this version of Windows has no way to ask the antivirus (amsi.dll is missing)")
	}
	a := &Asker{questions: make(chan question), done: make(chan struct{})}
	ready := make(chan error, 1)
	// The door belongs to one thread, so one goroutine keeps to its thread
	// and does all the asking.
	go func() {
		defer close(a.done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		leave, _ := com.Enter()
		defer leave()
		name, err := syscall.UTF16PtrFromString(app)
		if err != nil {
			ready <- err
			return
		}
		var context uintptr
		if r, _, _ := initialize.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&context))); r != 0 || context == 0 {
			ready <- fmt.Errorf("the antivirus could not be asked (0x%08X)", uint32(r))
			return
		}
		defer uninitialize.Call(context)
		ready <- nil
		for q := range a.questions {
			q.reply <- ask(context, q.content, q.name)
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return a, nil
}

// ask hands one piece of content over, on the thread that owns the door.
func ask(context uintptr, content []byte, name string) reply {
	if len(content) == 0 {
		return reply{NotAsked, nil}
	}
	if len(content) > Most {
		content = content[:Most]
	}
	what, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		what, _ = syscall.UTF16PtrFromString("content")
	}
	var result uint32
	r, _, _ := scanBuffer.Call(context, uintptr(unsafe.Pointer(&content[0])), uintptr(len(content)), uintptr(unsafe.Pointer(what)), 0, uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(content)
	if r != 0 {
		return reply{NotAsked, fmt.Errorf("the antivirus did not answer (0x%08X)", uint32(r))}
	}
	return reply{Read(result), nil}
}

// Read puts the number the antivirus answers with into words. Windows
// defines the ranges: from 32768 up means harmful, and 16384 to 20479
// means that an administrator's rule forbids the content.
func Read(result uint32) Answer {
	switch {
	case result >= 32768:
		return Harmful
	case result >= 0x4000 && result <= 0x4FFF:
		return Forbidden
	}
	return NoObjection
}

// Ask hands a piece of content to the antivirus. name says what it is: a
// file's path, or a few words. Content larger than Most is cut to that.
func (a *Asker) Ask(content []byte, name string) (Answer, error) {
	if a == nil {
		return NotAsked, nil
	}
	q := question{content: content, name: name, reply: make(chan reply, 1)}
	select {
	case a.questions <- q:
	case <-a.done:
		return NotAsked, errors.New("the antivirus is no longer being asked")
	}
	r := <-q.reply
	return r.answer, r.err
}

// Close shuts the door.
func (a *Asker) Close() {
	if a == nil {
		return
	}
	close(a.questions)
	<-a.done
}
