package history

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
)

var folders = model.Folders{Windows: `C:\Windows`, System: `C:\Windows\System32`, ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`,
	Profile: `C:\Users\sam`, Downloads: `C:\Users\sam\Downloads`}

func TestRot13(t *testing.T) {
	if got := rot13("HRZR_PGYPHNPbhag:pgbe"); got != "UEME_CTLCUACount:ctor" {
		t.Errorf("got %q", got)
	}
	if got := rot13(rot13(`C:\Program Files\Tool 2\tool.exe`)); got != `C:\Program Files\Tool 2\tool.exe` {
		t.Errorf("twice gave %q", got)
	}
}

// record makes a UserAssist value as Windows 7 and later write it.
func record(count, focusMS uint32, last time.Time) []byte {
	data := make([]byte, 72)
	binary.LittleEndian.PutUint32(data[4:], count)
	binary.LittleEndian.PutUint32(data[12:], focusMS)
	if !last.IsZero() {
		binary.LittleEndian.PutUint64(data[60:], uint64(last.UnixNano()/100)+116444736000000000)
	}
	return data
}

func TestUserAssist(t *testing.T) {
	when := time.Date(2026, 11, 20, 18, 30, 0, 0, time.UTC)
	r, ok := UserAssist(rot13(`{6D809377-6AF0-444B-8957-A3773F02200E}\Tool\tool.exe`), record(14, 420000, when), folders)
	if !ok || r.Path != `C:\Program Files\Tool\tool.exe` || r.Count != 14 || r.Focus != 7*time.Minute || !r.Last.Equal(when) || r.Source != "UserAssist" {
		t.Errorf("got %+v, %v", r, ok)
	}
	r, ok = UserAssist(rot13(`{374DE290-123F-4565-9164-39C4925E467B}\setup.exe`), record(1, 0, when), folders)
	if !ok || r.Path != `C:\Users\sam\Downloads\setup.exe` {
		t.Errorf("a download gave %+v", r)
	}
	r, ok = UserAssist(rot13(`Microsoft.WindowsCalculator_8wekyb3d8bbwe!App`), record(3, 0, when), folders)
	if !ok || r.Path != "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" {
		t.Errorf("an app gave %+v", r)
	}
	for _, bad := range []struct {
		name string
		data []byte
	}{
		{rot13("UEME_CTLSESSION"), record(1, 0, when)},     // Windows' own counter
		{rot13(`C:\x.exe`), record(1, 0, when)[:16]},       // too short to be a record
		{rot13(`C:\never.exe`), record(0, 0, time.Time{})}, // never run
	} {
		if r, ok := UserAssist(bad.name, bad.data, folders); ok {
			t.Errorf("%q gave %+v", rot13(bad.name), r)
		}
	}
}

func TestBAM(t *testing.T) {
	when := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data, uint64(when.UnixNano()/100)+116444736000000000)
	drive := func(p string) string {
		if strings.HasPrefix(p, `\Device\HarddiskVolume3\`) {
			return `C:\` + p[len(`\Device\HarddiskVolume3\`):]
		}
		return ""
	}
	r, ok := BAM(`\Device\HarddiskVolume3\Tools\tool.exe`, data, drive)
	if !ok || r.Path != `C:\Tools\tool.exe` || !r.Last.Equal(when) || r.Source != "BAM" {
		t.Errorf("got %+v, %v", r, ok)
	}
	if _, ok := BAM("Version", []byte{1, 0, 0, 0}, drive); ok {
		t.Error("the Version value was read as a program")
	}
	if r, ok := BAM(`\Device\HarddiskVolume9\x.exe`, data, drive); !ok || r.Path != `\Device\HarddiskVolume9\x.exe` {
		t.Errorf("a path on an unknown drive gave %+v", r)
	}
}

func TestZone(t *testing.T) {
	o, ok := Zone("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/page\r\nHostUrl=https://example.com/file.exe\r\n")
	if !ok || o.Zone != 3 || o.Host != "https://example.com/file.exe" || o.Referrer != "https://example.com/page" {
		t.Errorf("got %+v, %v", o, ok)
	}
	if o, ok := Zone("[ZoneTransfer]\nZoneId=3\n"); !ok || o.Zone != 3 || o.Host != "" {
		t.Errorf("a mark with no address gave %+v", o)
	}
	if _, ok := Zone("nothing here"); ok {
		t.Error("a file with no zone was read as marked")
	}
	if o, _ := Zone("ZoneId=3\nHostUrl=https://x/\x07" + strings.Repeat("a", 400)); len([]rune(o.Host)) > 300 || strings.ContainsRune(o.Host, 7) {
		t.Errorf("a long or odd address was kept as it was: %d characters", len(o.Host))
	}
}

// TestLive reads this PC's records. It runs only when LAZASCOPE_LIVE=1.
func TestLive(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") != "1" {
		t.Skip("set LAZASCOPE_LIVE=1 to read this PC's records")
	}
	home, _ := os.UserHomeDir()
	runs, gaps := Collect(model.Folders{Profile: home, ProgramFiles: os.Getenv("ProgramFiles"), ProgramFilesX86: os.Getenv("ProgramFiles(x86)"),
		Windows: os.Getenv("SystemRoot"), System: os.Getenv("SystemRoot") + `\System32`, Downloads: home + `\Downloads`}, false)
	users, bams := 0, 0
	for _, r := range runs {
		switch r.Source {
		case "UserAssist":
			users++
		case "BAM":
			bams++
		}
	}
	t.Logf("%d UserAssist records, %d BAM records, gaps: %v", users, bams, gaps)
	if users == 0 {
		t.Error("no UserAssist record was read")
	}
	for i := 1; i < len(runs); i++ {
		if runs[i].Last.After(runs[i-1].Last) {
			t.Fatal("the records are not newest first")
		}
	}
}
