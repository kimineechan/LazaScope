//go:build windows

package netconn

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestLiveNames reads the names Windows remembers and checks the promise
// the reading rests on: asking about a name Windows has never heard of
// gives nothing back, and leaves no trace of having been asked. It runs
// only when asked for:
//
//	set LAZASCOPE_LIVE=1
//	go test ./internal/netconn -run TestLive -v
//
// Compare what it prints with: ipconfig /displaydns
func TestLiveNames(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") == "" {
		t.Skip("set LAZASCOPE_LIVE=1 to read the names this PC remembers")
	}
	began := time.Now()
	names := Names()
	t.Logf("%d addresses have a name, read in %v", len(names), time.Since(began))
	var addresses []string
	for address := range names {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	for i, address := range addresses {
		if i >= 12 {
			break
		}
		t.Logf("    %-40s %s", address, strings.Join(names[address], ", "))
	}

	// A name that cannot have been looked up before.
	unheard := fmt.Sprintf("lazascope-never-asked-%d.example", time.Now().UnixNano())
	name, err := syscall.UTF16PtrFromString(unheard)
	if err != nil {
		t.Fatal(err)
	}
	began = time.Now()
	if got := remembered(name, addressV4); len(got) != 0 {
		t.Errorf("a name never looked up came back with %v", got)
	}
	took := time.Since(began)
	t.Logf("asking for %s took %v and gave nothing", unheard, took)
	// A real lookup that fails takes a network round trip, or seconds when
	// there is no network. An answer from memory comes at once.
	if took > 200*time.Millisecond {
		t.Errorf("the question took %v, which is long enough to have gone out on the network", took)
	}
	// And Windows did not note the name down, as it does after a real
	// lookup, even one that failed.
	for address, list := range Names() {
		for _, name := range list {
			if strings.EqualFold(name, unheard) {
				t.Errorf("the name was noted down, for %s", address)
			}
		}
	}
	if noted(unheard) {
		t.Error("the name is now in Windows' note of lookups, so a lookup was made")
	}
}

// noted reports whether a name is in Windows' note of recent lookups, with
// or without an address.
func noted(name string) bool {
	var first *cacheEntry
	if ok, _, _ := cacheTable.Call(uintptr(ptr(&first))); ok == 0 {
		return false
	}
	found := false
	for entry := first; entry != nil; {
		next := entry.next
		if entry.name != nil {
			if strings.EqualFold(strings.TrimSuffix(text(entry.name), "."), name) {
				found = true
			}
			dnsFree.Call(uintptr(ptr(entry.name)), freeFlat)
		}
		dnsFree.Call(uintptr(ptr(entry)), freeFlat)
		entry = next
	}
	return found
}

// ptr turns a typed pointer into the kind a Windows call takes.
func ptr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }
