//go:build windows

package scan

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

// A collector that goes wrong must leave a note and nothing else: the look
// carries on, and the part it was reading is said to be unread.
func TestGuard(t *testing.T) {
	var gaps []model.Gap
	var list []int
	guard(model.RunningNow, "What is running", &gaps, func() {
		var none []int
		list = append(list, none[3]) // goes wrong half way
	})
	if len(list) != 0 {
		t.Errorf("a collector that failed left %d results", len(list))
	}
	if len(gaps) != 1 || gaps[0].Area != model.RunningNow {
		t.Fatalf("got %+v, want one note for what is running", gaps)
	}
	for _, want := range []string{"What is running could not be read", "an error inside LazaScope itself", "index out of range", "Please report it."} {
		if !strings.Contains(gaps[0].What, want) {
			t.Errorf("the note lacks %q: %s", want, gaps[0].What)
		}
	}
	// A collector that works keeps its own notes and gains none.
	gaps = nil
	guard(model.Protection, "The state of the protections", &gaps, func() {
		gaps = []model.Gap{{Area: model.Protection, What: "The exclusions could not be read."}}
	})
	if len(gaps) != 1 || gaps[0].What != "The exclusions could not be read." {
		t.Errorf("got %+v", gaps)
	}
}
