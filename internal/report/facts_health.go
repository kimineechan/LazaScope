package report

import "lazascope/internal/model"

// What Windows' own logs say, in the data form of the report.

type jsonDetection struct {
	When     string `json:"when"`
	Threat   string `json:"threat"`
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
	Path     string `json:"path,omitempty"`
	Action   string `json:"action,omitempty"`
	Process  string `json:"process,omitempty"`
}

type jsonLoggedExclusion struct {
	When  string `json:"added"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type jsonFault struct {
	When      string `json:"when"`
	Corrected bool   `json:"corrected"`
	Part      string `json:"part"`
	Where     string `json:"where,omitempty"`
	Words     string `json:"words"`
	Record    int    `json:"record"` // the number Windows gives this kind of record
}

type jsonCrash struct {
	When string `json:"when"`
	Code uint32 `json:"stopCode"`
	Name string `json:"name,omitempty"`
}

type jsonWipe struct {
	When string `json:"when"`
	Log  string `json:"log"`
	By   string `json:"by,omitempty"`
}

type jsonDrive struct {
	Drive string `json:"drive"`
	Size  uint64 `json:"sizeBytes"`
	Free  uint64 `json:"freeBytes"`
}

type jsonHealth struct {
	LogReadable    bool        `json:"logReadable"`
	Days           int         `json:"days"` // how far back the look went
	HardwareErrors []jsonFault `json:"hardwareErrors"`
	BlueScreens    []jsonCrash `json:"blueScreens"`
	SuddenStops    []string    `json:"suddenStops"`
	DiskFaults     []jsonFault `json:"diskFaults"`
	DiskRetries    int         `json:"diskRetries"`
	LogsCleared    []jsonWipe  `json:"logsCleared"`
	Drives         []jsonDrive `json:"drives"`
	RunningSince   string      `json:"windowsRunningSince,omitempty"`
}

func faults(list []model.Fault) []jsonFault {
	out := []jsonFault{}
	for _, f := range list {
		out = append(out, jsonFault{stamp(f.When), !f.Fatal, f.Part, f.Where, f.Words, f.ID})
	}
	return out
}

// healthFacts turns the health of the PC into its data form.
func healthFacts(c model.Condition) jsonHealth {
	out := jsonHealth{LogReadable: c.Read, Days: c.Days, HardwareErrors: faults(c.Hardware), BlueScreens: []jsonCrash{}, SuddenStops: []string{},
		DiskFaults: faults(c.Disk), DiskRetries: c.Retries, LogsCleared: []jsonWipe{}, Drives: []jsonDrive{}, RunningSince: stamp(c.Started)}
	for _, crash := range c.Crashes {
		out.BlueScreens = append(out.BlueScreens, jsonCrash{stamp(crash.When), crash.Code, crash.Name})
	}
	for _, when := range c.PowerCuts {
		out.SuddenStops = append(out.SuddenStops, stamp(when))
	}
	for _, wipe := range c.Wiped {
		out.LogsCleared = append(out.LogsCleared, jsonWipe{stamp(wipe.When), wipe.Log, wipe.By})
	}
	for _, drive := range c.Drives {
		out.Drives = append(out.Drives, jsonDrive{drive.Letter, drive.Size, drive.Free})
	}
	return out
}

// history fills in what Microsoft Defender's own log says.
func history(g model.Guard, p *jsonProtection) {
	p.DefenderLogReadable = g.HistoryRead
	p.DefenderFound, p.DefenderLogExclusions, p.DefenderSwitchedOff = []jsonDetection{}, []jsonLoggedExclusion{}, []string{}
	for _, d := range g.Detections {
		p.DefenderFound = append(p.DefenderFound, jsonDetection{stamp(d.When), d.Threat, d.Severity, d.Category, d.Path, d.Action, d.Process})
	}
	for _, e := range g.LoggedExclusions {
		p.DefenderLogExclusions = append(p.DefenderLogExclusions, jsonLoggedExclusion{stamp(e.When), e.Kind, e.Value})
	}
	for _, when := range g.SwitchedOff {
		p.DefenderSwitchedOff = append(p.DefenderSwitchedOff, stamp(when))
	}
}
