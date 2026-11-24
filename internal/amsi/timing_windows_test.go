//go:build windows

package amsi

import (
	"os"
	"testing"
	"time"
)

// TestLiveTiming measures how long the door takes to open and to answer,
// with an ordinary line only. It runs only when asked for.
func TestLiveTiming(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") == "" {
		t.Skip("set LAZASCOPE_LIVE=1 to ask this PC's antivirus")
	}
	began := time.Now()
	asker, err := Open("LazaScope test")
	if err != nil {
		t.Fatal(err)
	}
	opened := time.Since(began)
	began = time.Now()
	for i := 0; i < 20; i++ {
		if answer, err := asker.Ask([]byte("Write-Host 'hello'"), "LazaScope test: timing"); answer != NoObjection || err != nil {
			t.Fatalf("%v, %v", answer, err)
		}
	}
	each := time.Since(began) / 20
	began = time.Now()
	asker.Close()
	t.Logf("opening took %v, one question %v, closing %v", opened, each, time.Since(began))
}
