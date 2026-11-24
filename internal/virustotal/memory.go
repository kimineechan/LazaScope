package virustotal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"lazascope/internal/model"
)

// Memory keeps what VirusTotal said, so that a file is not asked about
// again for a week, and the fingerprints already worked out, so that a file
// that has not changed is not read again. It lives in one small file in
// LazaScope's own folder, and never holds the key.
//
// It is safe to use from several goroutines at once.
type Memory struct {
	mu   sync.Mutex
	path string // "" for a memory that is not kept on disk
	data memoryData
}

type memoryData struct {
	Version       int                         `json:"version"`
	AfterEachLook bool                        `json:"afterEachLook"` // ask about new files after every look
	Prints        map[string]Print            `json:"prints"`        // by path in small letters
	Answers       map[string]model.Reputation `json:"answers"`       // by fingerprint
}

// Print is a file's fingerprint, with what the file was like when it was
// worked out. A file of another size or time has changed since.
type Print struct {
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"` // nanoseconds since 1970, UTC
	SHA256   string `json:"sha256"`
}

// keep is how many fingerprints and answers a memory holds at most.
const keep = 5000

// OpenMemory reads the memory kept at path. A memory that is missing or
// cannot be read starts empty. path "" gives one that is never saved.
func OpenMemory(path string) *Memory {
	m := &Memory{path: path, data: memoryData{Version: 1, Prints: map[string]Print{}, Answers: map[string]model.Reputation{}}}
	if path == "" {
		return m
	}
	if content, err := os.ReadFile(path); err == nil {
		var data memoryData
		if json.Unmarshal(content, &data) == nil && data.Version == 1 {
			m.data.AfterEachLook = data.AfterEachLook
			for key, p := range data.Prints {
				if ValidHash(p.SHA256) {
					m.data.Prints[key] = p
				}
			}
			for print, r := range data.Answers {
				if ValidHash(print) {
					m.data.Answers[print] = r
				}
			}
		}
	}
	return m
}

// Save writes the memory to its file, in full, by writing a new file and
// putting it in place of the old one, so that a reader never sees half.
func (m *Memory) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path == "" {
		return nil
	}
	content, err := json.Marshal(m.data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	temporary := m.path + ".new"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, m.path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}

// Forget empties the memory and removes its file.
func (m *Memory) Forget() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = memoryData{Version: 1, Prints: map[string]Print{}, Answers: map[string]model.Reputation{}}
	if m.path == "" {
		return nil
	}
	if err := os.Remove(m.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// AfterEachLook reports whether new files are to be asked about after
// every look.
func (m *Memory) AfterEachLook() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data.AfterEachLook
}

// SetAfterEachLook changes that.
func (m *Memory) SetAfterEachLook(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data.AfterEachLook = on
}

// Answer returns what VirusTotal said about a file, if it was asked.
func (m *Memory) Answer(print string) (model.Reputation, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.data.Answers[strings.ToLower(print)]
	return r, ok
}

// Answers returns how many answers the memory holds.
func (m *Memory) Answers() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.data.Answers)
}

// Keep remembers what VirusTotal said about a file.
func (m *Memory) Keep(print string, r model.Reputation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data.Answers[strings.ToLower(print)] = r
	if len(m.data.Answers) > keep {
		// The answers asked longest ago go first.
		type aged struct {
			print string
			asked time.Time
		}
		var all []aged
		for p, answer := range m.data.Answers {
			all = append(all, aged{p, answer.Asked})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].asked.Before(all[j].asked) })
		for _, old := range all[:len(all)-keep] {
			delete(m.data.Answers, old.print)
		}
	}
}

// Print returns the fingerprint worked out earlier for a file, if the file
// has the same size and time as it had then.
func (m *Memory) Print(path string, size int64, modified time.Time) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.data.Prints[strings.ToLower(path)]
	if !ok || p.Size != size || p.Modified != modified.UnixNano() {
		return "", false
	}
	return p.SHA256, true
}

// KeepPrint remembers a file's fingerprint, with its size and time.
func (m *Memory) KeepPrint(path string, size int64, modified time.Time, print string) {
	if !ValidHash(print) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.data.Prints) >= keep {
		// A tenth makes room; which ones hardly matters, as a fingerprint is
		// only ever worked out again.
		drop := keep / 10
		for key := range m.data.Prints {
			if drop == 0 {
				break
			}
			delete(m.data.Prints, key)
			drop--
		}
	}
	m.data.Prints[strings.ToLower(path)] = Print{size, modified.UnixNano(), print}
}

// Apply puts what the memory holds into a look: the fingerprint of each
// file it knows that has not changed since, and what VirusTotal said about
// each file it was asked about. It returns how many files have an answer.
func (m *Memory) Apply(s *model.Snapshot) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Fingerprints == nil {
		s.Fingerprints = map[string]string{}
	}
	if s.VirusTotal == nil {
		s.VirusTotal = map[string]model.Reputation{}
	}
	answered := 0
	use := func(f model.File) {
		if f.Path == "" || !f.Exists {
			return
		}
		key := strings.ToLower(f.Path)
		print := s.Fingerprints[key]
		if p, ok := m.data.Prints[key]; ok && print == "" && p.Size == f.Size && p.Modified == f.Modified.UnixNano() {
			print = p.SHA256
			s.Fingerprints[key] = print
		}
		if r, ok := m.data.Answers[print]; ok && print != "" {
			if _, already := s.VirusTotal[print]; !already {
				answered++
			}
			s.VirusTotal[print] = r
		}
	}
	for _, e := range s.Startup {
		use(e.Program)
		use(e.Target)
	}
	for _, p := range s.Processes {
		use(p.File)
	}
	for _, c := range s.Connections {
		use(c.File)
	}
	return answered
}
