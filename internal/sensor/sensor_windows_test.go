//go:build windows

package sensor

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"lazascope/internal/detect"
)

func TestWhen(t *testing.T) {
	got := When("20261124221503.123456+060")
	want := time.Date(2026, 11, 24, 21, 15, 3, 123456000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !When("short").IsZero() || !When("20261124221503.123456+0x0").IsZero() {
		t.Error("a broken time was read")
	}
}

// TestLive starts the watch, starts a harmless program (the command prompt,
// told only to say a word and stop), and checks that the watch saw it with
// its parent and its command line. It runs only when LAZASCOPE_LIVE=1.
func TestLive(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") != "1" {
		t.Skip("set LAZASCOPE_LIVE=1 to watch this PC")
	}
	stop := make(chan struct{})
	seen := make(chan detect.Event, 64)
	done := make(chan error, 1)
	go func() { done <- Watch(stop, func(e detect.Event) { seen <- e }) }()
	time.Sleep(2 * time.Second) // let WMI begin
	marker := "lazascope-sensor-test-" + time.Now().Format("150405")
	cmd := exec.Command(os.Getenv("ComSpec"), "/c", "ping -n 3 127.0.0.1 >nul & echo "+marker)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	defer cmd.Wait()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-seen:
			if e.PID == pid {
				close(stop)
				<-done
				t.Logf("saw %s (%d) started by %q: %s", e.Name, e.PID, e.By, e.Command)
				if !strings.EqualFold(e.Name, "cmd.exe") || !strings.Contains(e.Command, marker) || e.When.IsZero() {
					t.Errorf("the event is incomplete: %+v", e)
				}
				return
			}
		case err := <-done:
			t.Fatalf("the watch ended: %v", err)
		case <-deadline:
			close(stop)
			t.Fatal("the watch did not see the program start within 10 seconds")
		}
	}
}
