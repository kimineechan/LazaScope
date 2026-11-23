//go:build windows

package eventlog

import (
	"os"
	"strings"
	"testing"
)

// TestLive reads this PC's own logs and prints what came back, to compare
// by eye with Event Viewer. It runs only when asked for:
//
//	set LAZASCOPE_LIVE=1
//	go test ./internal/eventlog -run TestLive -v
func TestLive(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") == "" {
		t.Skip("set LAZASCOPE_LIVE=1 to read this PC's logs")
	}
	for _, ask := range []struct{ log, question string }{
		{"System", Where(From("Microsoft-Windows-WHEA-Logger"), Since(90))},
		{"System", Where(From("Microsoft-Windows-WER-SystemErrorReporting"), Numbered(1001), Since(90))},
		{"System", Where(From("Microsoft-Windows-Kernel-Power"), Numbered(41), Since(90))},
		{"System", Where(From("disk"), Since(90))},
		{"System", Where(Numbered(104), Since(365))},
		{"Microsoft-Windows-Windows Defender/Operational", Where(Numbered(1006, 1015, 1116, 1117), Since(365))},
		{"Microsoft-Windows-Windows Defender/Operational", Where(Numbered(5001, 5007), Since(365))},
		{"Security", Where(Numbered(4625), Since(7))},
		{"No such log", Where(Numbered(1))},
	} {
		events, err := Read(ask.log, ask.question, 400)
		t.Logf("%s  %s\n    %d records, error: %v", ask.log, ask.question, len(events), err)
		for i, e := range events {
			if i >= 3 {
				break
			}
			words := strings.Join(strings.Fields(e.Message), " ")
			if len(words) > 260 {
				words = words[:260] + "..."
			}
			t.Logf("    %s  %s %d level %d  data %v loose %v\n        %s", e.Time.Local().Format("2006-01-02 15:04:05"), e.Provider, e.ID, e.Level, e.Data, e.Loose, words)
		}
	}
}
