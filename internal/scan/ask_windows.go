//go:build windows

package scan

import (
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"lazascope/internal/amsi"
	"lazascope/internal/eventlog"
	"lazascope/internal/model"
	"lazascope/internal/protect"
	"lazascope/internal/rules"
	"lazascope/internal/scripts"
)

// askAntivirus hands every script that starts by itself, and every command
// that a start-up entry or a running program carries on its line, to the
// antivirus installed on this PC, and notes what it said.
//
// LazaScope has no detection engine and passes no judgement of its own.
// This is the judgement of the product that is already there, asked
// through the door Windows keeps for the purpose. Nothing is run.
func askAntivirus(s *model.Snapshot) {
	asker, err := amsi.Open("LazaScope")
	if err != nil {
		s.Gaps = append(s.Gaps, model.Gap{Area: model.StartsWithWindows, What: "The antivirus could not be asked about scripts and hidden commands: " + err.Error() + "."})
		return
	}
	defer asker.Close()
	s.Engine = "The antivirus on this PC"
	for _, product := range s.Guard.Antivirus {
		if product.On == model.Yes {
			s.Engine = product.Name
			break
		}
	}

	self, _ := os.Executable()
	asked := map[string]model.Opinion{}
	ask := func(key string, content func() []byte, name string) model.Opinion {
		if opinion, done := asked[key]; done {
			return opinion
		}
		var opinion model.Opinion
		if data := content(); len(data) > 0 {
			before := time.Now()
			if answer, err := asker.Ask(data, name); err == nil && answer != amsi.NotAsked {
				opinion.Asked, opinion.Harmful = true, answer == amsi.Harmful
				if opinion.Harmful {
					opinion.Name = named(self, before)
				}
			}
		}
		asked[key] = opinion
		return opinion
	}
	file := func(f *model.File) {
		if !f.Exists || f.Program || !scripts.Is(f.Path) || scripts.Encoded(f.Path) || f.Size > amsi.Most {
			return
		}
		f.Opinion = ask("file:"+strings.ToLower(f.Path), func() []byte {
			data, _ := os.ReadFile(f.Path)
			return data
		}, f.Path)
	}
	command := func(program, line, what string) model.Opinion {
		carried := rules.Carried(program, line)
		if carried == "" {
			return model.Opinion{}
		}
		// PowerShell hands the antivirus its commands two bytes to a letter,
		// and what the antivirus knows is written against that form.
		return ask("command:"+carried, func() []byte { return wide(carried) }, what)
	}
	for i := range s.Startup {
		e := &s.Startup[i]
		file(&e.Target)
		if e.Command != "" && e.Extension == nil {
			e.Said = command(e.Program.Path, e.Command, "the command of the start-up entry "+e.Shown())
		}
	}
	for i := range s.Processes {
		p := &s.Processes[i]
		if p.Command != "" && !p.Self {
			p.Said = command(p.File.Path, p.Command, "the command line of "+p.Name)
		}
	}
}

// wide writes text two bytes to a letter, as Windows itself does.
func wide(text string) []byte {
	units := utf16.Encode([]rune(text))
	out := make([]byte, 2*len(units))
	for i, unit := range units {
		out[2*i], out[2*i+1] = byte(unit), byte(unit>>8)
	}
	return out
}

// named looks in Microsoft Defender's own log for the name it gave to what
// it has just called harmful. The door through which it was asked gives a
// yes or a no and nothing more. Another maker's antivirus keeps no such
// log here, and then there is no name.
func named(self string, since time.Time) string {
	const lastMinute = "*[System[EventID=1116 and TimeCreated[timediff(@SystemTime) <= 60000]]]"
	// Defender writes the record a moment after it answers.
	for range 10 {
		time.Sleep(250 * time.Millisecond)
		records, err := eventlog.ReadPlain(protect.HistoryLog, lastMinute, 20)
		if err != nil {
			return ""
		}
		for _, record := range records {
			if record.Time.Before(since.Add(-2*time.Second)) || !strings.EqualFold(record.Value("Source Name"), "AMSI") {
				continue
			}
			if process := record.Value("Process Name"); self != "" && !strings.EqualFold(process, self) {
				continue
			}
			if name := record.Value("Threat Name"); name != "" {
				return name
			}
		}
	}
	return ""
}
