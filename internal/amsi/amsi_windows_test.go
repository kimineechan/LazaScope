//go:build windows

package amsi

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// sample returns the harmless line of text that every antivirus behind this
// door agrees to call harmful, so that the door itself can be tested.
//
// It is put together when the test runs and is never written out whole,
// here or in the test program. Written whole, an antivirus finds it in the
// file and stops the file being read, which happened the first time this
// test was written.
func sample() string {
	return strings.Join([]string{"AMSI", "Test", "Sample:", strings.Join([]string{"7e72c3ce", "861b", "4339", "8740", "0ac1484c1386"}, "-")}, " ")
}

func TestRead(t *testing.T) {
	for result, want := range map[uint32]Answer{
		0: NoObjection, 1: NoObjection, 2: NoObjection, 16383: NoObjection,
		16384: Forbidden, 20479: Forbidden, 20480: NoObjection, 32767: NoObjection,
		32768: Harmful, 32769: Harmful, 0xFFFFFFFF: Harmful,
	} {
		if got := Read(result); got != want {
			t.Errorf("Read(%d) = %v, want %v", result, got, want)
		}
	}
	for answer, want := range map[Answer]string{NotAsked: "not asked", NoObjection: "no objection", Harmful: "harmful", Forbidden: "forbidden by a rule"} {
		if answer.String() != want {
			t.Errorf("%d is worded %q", answer, answer.String())
		}
	}
}

// Asking with nothing in hand, and asking a door that was never opened,
// must both be safe.
func TestNothingToAsk(t *testing.T) {
	var none *Asker
	if answer, err := none.Ask([]byte("echo hello"), "x"); answer != NotAsked || err != nil {
		t.Errorf("a door that was never opened answered %v, %v", answer, err)
	}
	none.Close()
}

// TestLive asks this PC's own antivirus. It hands over an ordinary line,
// which must raise no objection, and the test line every antivirus agrees
// to call harmful. The second makes the antivirus write a detection named
// as a test into its own log, and it may show a notice, so the test runs
// only when asked for:
//
//	set LAZASCOPE_LIVE=1
//	go test ./internal/amsi -run TestLive -v
func TestLive(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") == "" {
		t.Skip("set LAZASCOPE_LIVE=1 to ask this PC's antivirus")
	}
	asker, err := Open("LazaScope test")
	if err != nil {
		t.Fatalf("the antivirus could not be asked: %v", err)
	}
	defer asker.Close()

	ordinary, err := asker.Ask([]byte("@echo off\r\necho Good morning\r\n"), "LazaScope test: an ordinary batch file")
	t.Logf("an ordinary batch file: %v, %v", ordinary, err)
	if ordinary != NoObjection || err != nil {
		t.Errorf("an ordinary batch file got %v, %v", ordinary, err)
	}
	harmless, err := asker.Ask([]byte(sample()), "LazaScope test: the standard harmless test line")
	t.Logf("the standard test line: %v, %v", harmless, err)
	if harmless != Harmful {
		t.Errorf("the test line that every antivirus calls harmful got %v, %v. Is real-time protection on?", harmless, err)
	}
	if nothing, err := asker.Ask(nil, "nothing"); nothing != NotAsked || err != nil {
		t.Errorf("nothing at all got %v, %v", nothing, err)
	}

	// Several askers at once, as the look does.
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if answer, err := asker.Ask([]byte("Write-Host 'hello'"), "LazaScope test: one of several"); answer != NoObjection || err != nil {
				t.Errorf("asked alongside others: %v, %v", answer, err)
			}
		}()
	}
	wait.Wait()
}
