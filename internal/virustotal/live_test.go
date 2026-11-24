package virustotal

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestLiveWrongKey asks the real VirusTotal, once, with a key that cannot
// be anyone's, about the fingerprint of an empty file. It proves the whole
// path (the secure connection, the address, the heading that carries the
// key and the reading of a refusal) without anyone's key and without
// saying anything about the PC. It runs only when LAZASCOPE_LIVE=1.
func TestLiveWrongKey(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") != "1" {
		t.Skip("set LAZASCOPE_LIVE=1 to ask the real VirusTotal")
	}
	c, err := New(strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Look(context.Background(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	var refusal *Error
	if !errors.As(err, &refusal) || !errors.Is(err, ErrKey) || !Fatal(err) {
		t.Fatalf("VirusTotal's answer to a wrong key was read as %v", err)
	}
	t.Logf("VirusTotal answered %d %s: %q, read as: %v", refusal.Status, refusal.Code, refusal.Message, err)
}
