package rules

import (
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
)

// answer gives a file a fingerprint and VirusTotal's answer about it.
func answer(s *model.Snapshot, path string, r model.Reputation) {
	if s.Fingerprints == nil {
		s.Fingerprints = map[string]string{}
	}
	if s.VirusTotal == nil {
		s.VirusTotal = map[string]model.Reputation{}
	}
	print := strings.Repeat("ab", 32)[:64-len(path)%10] + strings.Repeat("0", len(path)%10)
	s.Fingerprints[strings.ToLower(path)] = print
	s.VirusTotal[print] = r
}

func TestVirusTotal(t *testing.T) {
	asked := now.Add(-time.Hour)
	flags := func(malicious, suspicious int) model.Reputation {
		return model.Reputation{Asked: asked, Known: true, Malicious: malicious, Suspicious: suspicious, Undetected: 70 - malicious - suspicious,
			Analysed: now.AddDate(0, 0, -3), Label: "trojan.example/test", Names: []model.EngineName{{Engine: "Northwind AV", Name: "Trojan.Example"}}}
	}
	const tool = `C:\Program Files\Widget\widget.exe` // a program the healthy PC does not have
	cases := []struct {
		what   string
		answer model.Reputation
		change func(*model.Snapshot)
		want   string
	}{
		{"many engines flag a program that starts", flags(9, 1), add(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd"))), "startup-virustotal-flags:high"},
		{"a few engines flag it", flags(3, 0), add(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd"))), "startup-virustotal-flags:medium"},
		{"one engine flags it", flags(1, 0), add(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd"))), "startup-virustotal-flags:low"},
		{"engines only suspect it", flags(0, 4), add(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd"))), "startup-virustotal-flags:low"},
		{"no engine flags it", flags(0, 0), add(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd"))), ""},
		{"VirusTotal has never seen it", model.Reputation{Asked: asked}, add(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd"))), ""},
		{"the entry is switched off", flags(9, 0), add(off(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd")))), ""},
		{"a flagged program runs", flags(6, 0), run(model.Process{PID: 700, Name: "tool.exe", File: signed(tool, "Tool Ltd")}), "running-virustotal-flags:high"},
		{"a flagged program both starts and runs, flagged once", flags(6, 0), func(s *model.Snapshot) {
			add(entry(model.RunKey, "Tool", signed(tool, "Tool Ltd")))(s)
			run(model.Process{PID: 700, Name: "tool.exe", File: signed(tool, "Tool Ltd")}, model.Process{PID: 701, Name: "tool.exe", File: signed(tool, "Tool Ltd")})(s)
		}, "startup-virustotal-flags:high"},
	}
	for _, c := range cases {
		s := healthy()
		c.change(s)
		answer(s, tool, c.answer)
		findings := Check(s)
		if got := outcome(findings); got != c.want {
			t.Errorf("%s: got %q, want %q", c.what, got, c.want)
			continue
		}
		for _, f := range findings {
			text := f.Reason + " " + f.Advice
			for _, fact := range f.Facts {
				text += " " + fact.Label + ": " + fact.Value
			}
			for _, want := range []string{"VirusTotal, asked by this file's fingerprint", "not LazaScope's", "Northwind AV: Trojan.Example", "trojan.example/test"} {
				if !strings.Contains(text, want) {
					t.Errorf("%s: the finding does not say %q: %s", c.what, want, text)
				}
			}
			if len(f.Attack) != 0 {
				t.Errorf("%s: a reputation is no technique, but carries %v", c.what, f.Attack)
			}
		}
	}
}

func TestVirusTotalSays(t *testing.T) {
	for want, r := range map[string]model.Reputation{
		"VirusTotal has never seen this file":                                   {},
		"VirusTotal knows this file, but has no engines' verdicts on it yet":    {Known: true},
		"none of the 70 antivirus engines flags it":                             {Known: true, Undetected: 70},
		"3 of 70 antivirus engines flag it: 2 call it harmful and 1 suspicious": {Known: true, Malicious: 2, Suspicious: 1, Undetected: 67},
		"2 of 70 antivirus engines flag it, as suspicious rather than harmful":  {Known: true, Suspicious: 2, Undetected: 68},
		"5 of 70 antivirus engines flag it":                                     {Known: true, Malicious: 5, Undetected: 65},
	} {
		if got := VirusTotalSays(r); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
