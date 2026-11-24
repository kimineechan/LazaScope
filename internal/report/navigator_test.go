package report

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"lazascope/internal/rules"
)

// readLayer reads a layer back and checks what the Navigator's file format,
// version 4.5, requires of every layer.
func readLayer(t *testing.T, data []byte) layer {
	t.Helper()
	var l layer
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("the layer is not valid data: %v", err)
	}
	// Fields the format requires, and the values it allows.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"name", "domain", "versions"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("the layer lacks the required field %q", field)
		}
	}
	if l.Name == "" || l.Domain != "enterprise-attack" {
		t.Errorf("name %q, domain %q", l.Name, l.Domain)
	}
	if l.Versions.Layer != "4.5" {
		t.Errorf("the format version is %q, and must be 4.5", l.Versions.Layer)
	}
	if !atLeast(l.Versions.Navigator, "4.9.0") {
		t.Errorf("the Navigator version %q is below 4.9.0, which the format requires", l.Versions.Navigator)
	}
	if want, _, _ := strings.Cut(rules.AttackVersion, "."); l.Versions.Attack != want {
		t.Errorf("the ATT&CK version is %q, want %q", l.Versions.Attack, want)
	}
	if len(l.Gradient.Colors) < 2 || l.Gradient.MaxValue <= l.Gradient.MinValue {
		t.Errorf("the gradient breaks the format's rules: %+v", l.Gradient)
	}
	colour := regexp.MustCompile(`^#[0-9a-f]{6}$`)
	for _, c := range l.Gradient.Colors {
		if !colour.MatchString(c) {
			t.Errorf("the gradient colour %q is not a hexadecimal colour", c)
		}
	}
	for _, item := range l.LegendItems {
		if item.Label == "" || !colour.MatchString(item.Color) {
			t.Errorf("a legend item breaks the format's rules: %+v", item)
		}
	}
	number := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	for i, technique := range l.Techniques {
		if !number.MatchString(technique.TechniqueID) {
			t.Errorf("%q is not a technique number", technique.TechniqueID)
		}
		if technique.Score < l.Gradient.MinValue || technique.Score > l.Gradient.MaxValue {
			t.Errorf("%s has the score %d, outside the scale %d to %d", technique.TechniqueID, technique.Score, l.Gradient.MinValue, l.Gradient.MaxValue)
		}
		if !technique.Enabled || technique.Comment == "" || len(technique.Metadata) == 0 {
			t.Errorf("%s is switched off or says nothing", technique.TechniqueID)
		}
		if i > 0 && l.Techniques[i-1].TechniqueID >= technique.TechniqueID {
			t.Errorf("the techniques are not in order of number, or one is there twice: %s", technique.TechniqueID)
		}
	}
	return l
}

// atLeast compares two version numbers such as 5.2.0, part by part.
func atLeast(version, floor string) bool {
	have, want := strings.Split(version, "."), strings.Split(floor, ".")
	for i := range want {
		if i >= len(have) {
			return false
		}
		a, errA := strconv.Atoi(have[i])
		b, _ := strconv.Atoi(want[i])
		if errA != nil {
			return false
		}
		if a != b {
			return a > b
		}
	}
	return true
}

func TestAtLeast(t *testing.T) {
	for version, want := range map[string]bool{"5.2.0": true, "4.9.0": true, "4.10.1": true, "4.8.9": false, "3.9": false, "x": false} {
		if got := atLeast(version, "4.9.0"); got != want {
			t.Errorf("atLeast(%q) = %v", version, got)
		}
	}
}

// The layer of a look holds exactly the techniques the findings name, each
// coloured by the most pressing finding that names it.
func TestNavigatorLayer(t *testing.T) {
	b := book(nil)
	data, count := NavigatorLayer(b, "1.0.0")
	l := readLayer(t, data)
	if count != len(l.Techniques) || count == 0 {
		t.Fatalf("said %d techniques, wrote %d", count, len(l.Techniques))
	}
	want := map[string]int{}
	for _, f := range b.Findings {
		for _, technique := range rules.Techniques(f.Attack) {
			want[technique.ID] = max(want[technique.ID], score(f.Severity))
		}
	}
	if len(want) != len(l.Techniques) {
		t.Errorf("the findings name %d techniques, the layer holds %d", len(want), len(l.Techniques))
	}
	for _, technique := range l.Techniques {
		if technique.Score != want[technique.TechniqueID] {
			t.Errorf("%s scores %d, want %d", technique.TechniqueID, technique.Score, want[technique.TechniqueID])
		}
	}
	if !strings.Contains(l.Name, "STUDY-PC") || !strings.Contains(l.Description, "Read it before you send it to anyone.") {
		t.Errorf("the layer does not say which PC it is about, or does not warn: %q / %q", l.Name, l.Description)
	}
}

// The layer of what the rules look for holds every technique a rule can
// name, and nothing about any PC.
func TestCoverageLayer(t *testing.T) {
	data, count := CoverageLayer("1.0.0")
	l := readLayer(t, data)
	covered := rules.Covered()
	if count != len(covered) || len(l.Techniques) != len(covered) {
		t.Errorf("the rules name %d techniques, the layer holds %d and says %d", len(covered), len(l.Techniques), count)
	}
	for _, technique := range l.Techniques {
		if technique.Score != len(covered[technique.TechniqueID]) {
			t.Errorf("%s scores %d, but %d rules name it", technique.TechniqueID, technique.Score, len(covered[technique.TechniqueID]))
		}
	}
	if strings.Contains(string(data), "STUDY-PC") || strings.Contains(string(data), "Computer") {
		t.Error("the layer of what the rules look for holds something about a PC")
	}
}
