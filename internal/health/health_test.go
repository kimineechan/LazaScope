package health

import (
	"testing"
	"time"

	"lazascope/internal/eventlog"
)

var when = time.Date(2026, 11, 14, 11, 35, 57, 0, time.UTC)

func TestLine(t *testing.T) {
	message := "A corrected hardware error has occurred.\n\nReported by component: Processor Core\nError Source: Unknown Error Source\nError Type: Internal parity error\nProcessor APIC ID: 12\n\nThe details view of this entry contains further information."
	want := "A corrected hardware error has occurred. Reported by component: Processor Core. Error Source: Unknown Error Source. Error Type: Internal parity error. Processor APIC ID: 12."
	if got := Line(message); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := Line("  One   line,  with   gaps  "); got != "One line, with gaps." {
		t.Errorf("got %q", got)
	}
	if got := Line(""); got != "" {
		t.Errorf("an empty message gave %q", got)
	}
}

func TestHardware(t *testing.T) {
	core := eventlog.Event{Time: when, Provider: hardwareWriter, ID: 19, Level: eventlog.Warning, Data: map[string]string{"ApicId": "12", "ErrorType": "12"},
		Message: "A corrected hardware error has occurred.\nReported by component: Processor Core\nProcessor APIC ID: 12"}
	fault := Hardware(core)
	if fault.Fatal || fault.Part != "the processor" || fault.Where != "APIC ID 12" || fault.ID != 19 || !fault.When.Equal(when) {
		t.Errorf("a corrected processor error was read as %+v", fault)
	}
	if fault.Words != "A corrected hardware error has occurred. Reported by component: Processor Core. Processor APIC ID: 12." {
		t.Errorf("its words: %q", fault.Words)
	}

	fatal := Hardware(eventlog.Event{Time: when, ID: 18, Level: eventlog.Error, Data: map[string]string{"ApicId": "4"}})
	if !fatal.Fatal || fatal.Words != "A hardware error (record number 18 of WHEA-Logger)." {
		t.Errorf("a fatal error with no message was read as %+v", fatal)
	}
	if memory := Hardware(eventlog.Event{ID: 47, Level: eventlog.Warning, Data: map[string]string{}}); memory.Part != "the memory" || memory.Fatal || memory.Words != "A corrected hardware error (record number 47 of WHEA-Logger)." {
		t.Errorf("a memory error was read as %+v", memory)
	}
	if bus := Hardware(eventlog.Event{ID: 17, Level: eventlog.Warning, Data: map[string]string{"PrimaryBusNumber": "0x0"}}); bus.Part != "a part on the PCI Express bus, such as a graphics card, an SSD or a network card" {
		t.Errorf("a bus error was read as %+v", bus)
	}
	if other := Hardware(eventlog.Event{ID: 99, Level: eventlog.Warning, Data: map[string]string{}}); other.Part != "a part of the hardware" {
		t.Errorf("an unknown kind was read as %+v", other)
	}
}

func TestCrash(t *testing.T) {
	for _, test := range []struct {
		text string
		code uint32
		name string
		ok   bool
	}{
		{"0x00000050 (0xffff8b8b790ef188, 0x0000000000000011, 0xffff8b8b790ef188, 0x0000000000000002)", 0x50, "PAGE_FAULT_IN_NONPAGED_AREA", true},
		{"0x00020001 (0x0000000000000011, 0x0000000000210a2e, 0x0000000000001005, 0xfffff8a000000000)", 0x20001, "HYPERVISOR_ERROR", true},
		{"0x00000001 (0x1, 0x2, 0x3, 0x4)", 0x1, "APC_INDEX_MISMATCH", true},
		{"0x00000777", 0x777, "", true},
		{"0X0000003B (0x0)", 0x3B, "SYSTEM_SERVICE_EXCEPTION", true},
		{"", 0, "", false},
		{"not a number", 0, "", false},
		{"0x (0x1)", 0, "", false},
	} {
		crash, ok := Crash(eventlog.Event{Time: when, Data: map[string]string{"param1": test.text}})
		if ok != test.ok || crash.Code != test.code || crash.Name != test.name {
			t.Errorf("Crash(%q) = %+v, %v", test.text, crash, ok)
		}
	}
	// An older Windows gives the same text as a value without a name.
	if crash, ok := Crash(eventlog.Event{Loose: []string{"0x0000007e (0x1, 0x2, 0x3, 0x4)"}, Data: map[string]string{}}); !ok || crash.Code != 0x7E {
		t.Errorf("the nameless form was read as %+v, %v", crash, ok)
	}
}

func TestPowerCut(t *testing.T) {
	for code, cut := range map[string]bool{"0": true, "80": false, "0x50": false, "": true} {
		data := map[string]string{}
		if code != "" {
			data["BugcheckCode"] = code
		}
		if got := PowerCut(eventlog.Event{Data: data}); got != cut {
			t.Errorf("a stop with BugcheckCode %q: power cut = %v", code, got)
		}
	}
}

func TestDisk(t *testing.T) {
	for id, retry := range map[int]bool{7: false, 52: false, 55: false, 11: true, 51: true, 153: true} {
		fault, got := Disk(eventlog.Event{Time: when, ID: id, Loose: []string{`\Device\Harddisk1\DR2`}})
		if got != retry {
			t.Errorf("record %d: retry = %v", id, got)
		}
		if !retry && (fault.Words == "" || fault.Where != `\Device\Harddisk1\DR2` || fault.Part != "a disk") {
			t.Errorf("record %d was read as %+v", id, fault)
		}
		if fault.Fatal != (id == 52) {
			t.Errorf("record %d: fatal = %v", id, fault.Fatal)
		}
	}
	// Windows' own words are kept when it has them.
	fault, _ := Disk(eventlog.Event{ID: 7, Message: `The device, \Device\Harddisk0\DR0, has a bad block.`})
	if fault.Words != `The device, \Device\Harddisk0\DR0, has a bad block.` {
		t.Errorf("got %q", fault.Words)
	}
}

func TestWipe(t *testing.T) {
	wipe := Wipe(eventlog.Event{Time: when, ID: 104, Data: map[string]string{"Channel": "Application", "SubjectUserName": "sam"}}, "System")
	if wipe.Log != "Application" || wipe.By != "sam" || !wipe.When.Equal(when) {
		t.Errorf("got %+v", wipe)
	}
	if wipe := Wipe(eventlog.Event{ID: 1102, Data: map[string]string{}}, "Security"); wipe.Log != "Security" || wipe.By != "" {
		t.Errorf("got %+v", wipe)
	}
}

func TestStopCodes(t *testing.T) {
	if StopCode(0x124) != "WHEA_UNCORRECTABLE_ERROR" || StopCode(0xDEAD) != "" {
		t.Error("the list of stop codes is off")
	}
	for code, name := range stopCodes {
		if name == "" || name != trimmed(name) {
			t.Errorf("stop code 0x%X has the name %q", code, name)
		}
	}
}

func trimmed(text string) string {
	for len(text) > 0 && (text[0] == ' ' || text[len(text)-1] == ' ') {
		if text[0] == ' ' {
			text = text[1:]
		} else {
			text = text[:len(text)-1]
		}
	}
	return text
}
