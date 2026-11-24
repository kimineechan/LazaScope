package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/DETECTIONS.md must list every detection as the code has it, so that
// what is written is what runs.
func TestDetectionsAreDocumented(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "DETECTIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	rows := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "| `") {
			rows++
		}
	}
	for _, d := range All {
		var techniques []string
		for _, id := range d.Attack {
			techniques = append(techniques, id+" "+Techniques[id])
		}
		want := "| `" + d.ID + "` | " + d.Severity.String() + " | " + d.Title + " | " + d.Why + " | " + strings.Join(techniques, "; ") + " |"
		if !strings.Contains(text, want) {
			t.Errorf("docs/DETECTIONS.md is out of step for %s. Print the table again with: lazascope-cli detections --markdown", d.ID)
		}
	}
	if rows != len(All) {
		t.Errorf("docs/DETECTIONS.md lists %d detections and the program has %d", rows, len(All))
	}
}
