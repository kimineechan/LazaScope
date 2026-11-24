package report

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"lazascope/internal/rules"
	"lazascope/internal/view"
)

// The ATT&CK Navigator is MITRE's free web page that draws the whole ATT&CK
// catalogue as a grid of techniques, and colours in the ones a layer file
// names. Security teams use it to see at a glance what was found, or what a
// set of tools can see. LazaScope writes layers in the Navigator's own file
// format, version 4.5, so that a look at a PC can be laid over the
// catalogue, or what LazaScope's rules can see set beside other tools.

const (
	layerFormat      = "4.5"   // the version of the Navigator's file format these layers follow
	navigatorVersion = "5.2.0" // the Navigator named in that format's own example; any from 4.9.0 on reads it
)

// The colours of the three levels, the same as the window and the web page use.
const (
	colourFirst = "#d43b30"
	colourLook  = "#e0a11b"
	colourKnow  = "#9a9a9a"
)

type layer struct {
	Name                          string           `json:"name"`
	Versions                      layerVersions    `json:"versions"`
	Domain                        string           `json:"domain"`
	Description                   string           `json:"description"`
	Filters                       layerFilters     `json:"filters"`
	Sorting                       int              `json:"sorting"`
	Layout                        layerLayout      `json:"layout"`
	HideDisabled                  bool             `json:"hideDisabled"`
	Techniques                    []layerTechnique `json:"techniques"`
	Gradient                      layerGradient    `json:"gradient"`
	LegendItems                   []layerLegend    `json:"legendItems"`
	Metadata                      []layerMeta      `json:"metadata"`
	Links                         []layerLink      `json:"links"`
	ShowTacticRowBackground       bool             `json:"showTacticRowBackground"`
	TacticRowBackground           string           `json:"tacticRowBackground"`
	SelectTechniquesAcrossTactics bool             `json:"selectTechniquesAcrossTactics"`
	SelectSubtechniquesWithParent bool             `json:"selectSubtechniquesWithParent"`
	SelectVisibleTechniques       bool             `json:"selectVisibleTechniques"`
}

type layerVersions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

type layerFilters struct {
	Platforms []string `json:"platforms"`
}

type layerLayout struct {
	Layout                string `json:"layout"`
	ShowID                bool   `json:"showID"`
	ShowName              bool   `json:"showName"`
	ShowAggregateScores   bool   `json:"showAggregateScores"`
	CountUnscored         bool   `json:"countUnscored"`
	AggregateFunction     string `json:"aggregateFunction"`
	ExpandedSubtechniques string `json:"expandedSubtechniques"`
}

type layerTechnique struct {
	TechniqueID       string      `json:"techniqueID"`
	Score             int         `json:"score"`
	Color             string      `json:"color"`
	Comment           string      `json:"comment"`
	Enabled           bool        `json:"enabled"`
	Metadata          []layerMeta `json:"metadata"`
	Links             []layerLink `json:"links"`
	ShowSubtechniques bool        `json:"showSubtechniques"`
}

type layerGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type layerLegend struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

type layerMeta struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type layerLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// newLayer starts a layer with the settings every LazaScope layer shares.
func newLayer(name, description string) layer {
	attack, _, _ := strings.Cut(rules.AttackVersion, ".") // the Navigator names ATT&CK by its main number
	return layer{
		Name: name, Description: description, Domain: "enterprise-attack",
		Versions: layerVersions{Attack: attack, Navigator: navigatorVersion, Layer: layerFormat},
		Filters:  layerFilters{Platforms: []string{"Windows"}},
		Sorting:  3, // the highest score first
		Layout: layerLayout{Layout: "side", ShowID: true, ShowName: true, AggregateFunction: "max",
			ExpandedSubtechniques: "annotated"}, // a sub-technique LazaScope names is shown without being opened by hand
		Techniques: []layerTechnique{}, Metadata: []layerMeta{}, Links: []layerLink{}, LegendItems: []layerLegend{},
		TacticRowBackground: "#dddddd", SelectTechniquesAcrossTactics: true,
	}
}

func (l layer) bytes() []byte {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false) // a layer is not put into a web page, so "&" can stay "&"
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(l); err != nil {
		panic(err) // every field is a plain value; this cannot fail
	}
	return out.Bytes()
}

// score is how a finding's level shows in a layer: 3 to look at first, 2
// worth a look, 1 good to know.
func score(severity rules.Severity) int {
	switch severity {
	case rules.High:
		return 3
	case rules.Medium:
		return 2
	}
	return 1
}

// NavigatorLayer writes the techniques that the findings of a look are
// traces of, as a layer for the ATT&CK Navigator, and says how many there
// are. Each technique is coloured by the most pressing finding that names
// it, and lists every such finding.
func NavigatorLayer(b *view.Book, version string) ([]byte, int) {
	s := b.Snapshot
	when := s.Taken.Format("2 January 2006")
	l := newLayer("LazaScope: "+s.Computer+", "+when,
		"What LazaScope found on "+s.Computer+" on "+when+", laid over MITRE ATT&CK "+rules.AttackVersion+
			". Each technique is coloured by the most pressing finding that is a trace of it: red to look at first, amber worth a look, grey good to know. "+
			"A trace is a reason to look, not proof that anyone attacked this PC: the same signs mark plenty of honest software. "+Careful)
	l.Gradient = layerGradient{Colors: []string{colourKnow, colourLook, colourFirst}, MinValue: 1, MaxValue: 3}
	l.LegendItems = []layerLegend{{"Look first", colourFirst}, {"Worth a look", colourLook}, {"Good to know", colourKnow}}
	rights := "No"
	if s.Elevated {
		rights = "Yes"
	}
	l.Metadata = []layerMeta{{"Made by", "LazaScope " + version}, {"Computer", s.Computer}, {"Windows", s.Windows},
		{"Looked at", stamp(s.Taken)}, {"Administrator rights", rights}, {"ATT&CK version", rules.AttackVersion}}

	found := map[string]*layerTechnique{}
	for _, f := range b.Findings {
		for _, technique := range rules.Techniques(f.Attack) {
			t := found[technique.ID]
			if t == nil {
				t = &layerTechnique{TechniqueID: technique.ID, Enabled: true, Metadata: []layerMeta{}, Links: []layerLink{}}
				found[technique.ID] = t
			}
			t.Score = max(t.Score, score(f.Severity))
			t.Metadata = append(t.Metadata, layerMeta{f.Severity.String(), f.Title + " (" + f.Subject + "), rule " + f.Rule})
		}
	}
	for _, t := range found {
		n := len(t.Metadata)
		t.Comment = strconv.Itoa(n) + " finding"
		if n != 1 {
			t.Comment += "s"
		}
		t.Comment += " on " + s.Computer + " may be a trace of this technique."
		l.Techniques = append(l.Techniques, *t)
	}
	sort.Slice(l.Techniques, func(i, j int) bool { return l.Techniques[i].TechniqueID < l.Techniques[j].TechniqueID })
	return l.bytes(), len(l.Techniques)
}

// CoverageLayer writes every technique that LazaScope's rules can name, as
// a layer for the ATT&CK Navigator, and says how many there are. The more
// rules look for traces of a technique, the darker it is. It holds nothing
// about any PC.
func CoverageLayer(version string) ([]byte, int) {
	all := rules.All()
	l := newLayer("LazaScope: what its rules look for",
		"The MITRE ATT&CK "+rules.AttackVersion+" techniques whose traces LazaScope "+version+"'s "+strconv.Itoa(len(all))+
			" rules look for on a Windows PC. The more rules look for a technique, the darker it is. "+
			"A rule sees only the traces it was written for, so a technique coloured here is watched for, not ruled out.")
	l.Metadata = []layerMeta{{"Made by", "LazaScope " + version}, {"Rules", strconv.Itoa(len(all))}, {"ATT&CK version", rules.AttackVersion}}
	titles := map[string]string{}
	for _, rule := range all {
		titles[rule.ID] = rule.Title
	}
	most := 1
	for id, named := range rules.Covered() {
		t := layerTechnique{TechniqueID: id, Score: len(named), Enabled: true, Metadata: []layerMeta{}, Links: []layerLink{}}
		for _, rule := range named {
			t.Metadata = append(t.Metadata, layerMeta{"Rule " + rule, titles[rule]})
		}
		t.Comment = "Looked for by " + strings.Join(named, ", ") + "."
		most = max(most, len(named))
		l.Techniques = append(l.Techniques, t)
	}
	sort.Slice(l.Techniques, func(i, j int) bool { return l.Techniques[i].TechniqueID < l.Techniques[j].TechniqueID })
	// The Navigator needs the top of the scale above its foot.
	l.Gradient = layerGradient{Colors: []string{"#c9e7d3", "#2e9d57"}, MinValue: 1, MaxValue: max(most, 2)}
	l.LegendItems = []layerLegend{{"Looked for by one rule", "#c9e7d3"}, {"Looked for by " + strconv.Itoa(max(most, 2)) + " rules", "#2e9d57"}}
	return l.bytes(), len(l.Techniques)
}
