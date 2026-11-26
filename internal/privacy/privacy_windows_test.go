//go:build windows

package privacy

import (
	"os"
	"testing"

	"lazascope/internal/procs"
)

// TestLive reads this PC's protections and prints them, to compare by eye
// with Windows Security and System Information. It runs only when
// LAZASCOPE_LIVE=1.
func TestLive(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") != "1" {
		t.Skip("set LAZASCOPE_LIVE=1 to read this PC's protections")
	}
	table, err := procs.Table()
	if err != nil {
		t.Fatal(err)
	}
	start := lsassStart(table)
	if start.IsZero() {
		t.Fatal("no LSASS was found in session 0")
	}
	protected, logged := lsaLog()
	t.Logf("LSASS started %s; the System log reaches back to it: %v; started as a protected process: %v", start.Local().Format("2006-01-02 15:04:05"), logged, protected)
	// Wininit writes more than one note as it starts LSASS. Asking for its
	// note on Credential Guard's set-up (14) shows that the question finds a
	// note that is there, on a PC that writes that one.
	setup, _ := noted("Microsoft-Windows-Wininit", 14, start)
	t.Logf("Wininit's note 14 since LSASS started: %v", setup)
	running, asked := hvciRunning()
	t.Logf("memory integrity running: %v (Windows could be asked: %v); Windows build %d", running, asked, windowsBuild())
	for _, d := range Defences() {
		t.Logf("%-12s %-9s %s", d.Key, d.On, d.Note)
	}
}
