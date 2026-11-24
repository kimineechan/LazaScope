//go:build windows

package virustotal

import (
	"bytes"
	"testing"
)

// A sealed key opens again for this account, does not show the key, and a
// damaged seal does not open at all. Nothing is written to disk.
func TestSeal(t *testing.T) {
	sealed, err := seal([]byte(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(testKey)) || bytes.Contains(sealed, []byte(testKey[:16])) {
		t.Fatal("the sealed key shows the key")
	}
	plain, err := unseal(sealed)
	if err != nil || string(plain) != testKey {
		t.Fatalf("the seal opened to %q, %v", plain, err)
	}
	damaged := append([]byte{}, sealed...)
	damaged[len(damaged)/2] ^= 0xFF
	if plain, err := unseal(damaged); err == nil {
		t.Errorf("a damaged seal opened to %q", plain)
	}
	if _, err := unseal([]byte("not a seal")); err == nil {
		t.Error("something that is not a seal opened")
	}
}

func TestFolder(t *testing.T) {
	folder, err := Folder()
	if err != nil || folder == "" {
		t.Fatalf("got %q, %v", folder, err)
	}
	if path, err := MemoryPath(); err != nil || path == folder {
		t.Errorf("got %q, %v", path, err)
	}
}
