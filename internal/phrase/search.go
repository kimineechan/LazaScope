package phrase

import (
	"archive/zip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"lazascope/internal/model"
)

// kinds are the kinds of file that are read: the ones people keep notes
// in, and the settings files developers keep a test wallet's phrase in.
// Program code is not read: it holds test phrases and word lists of its own.
var kinds = map[string]bool{
	".txt": true, ".text": true, ".md": true, ".markdown": true, ".rtf": true, ".docx": true, ".odt": true,
	".csv": true, ".tsv": true, ".json": true, ".log": true, ".html": true, ".htm": true, ".xml": true,
	".ini": true, ".cfg": true, ".conf": true, ".yaml": true, ".yml": true, ".env": true,
	".bak": true, ".old": true, ".note": true,
}

// skip are folders that are never entered: other programs' own data, which
// lives in AppData and is not a place people write notes, and the folders
// of code and its tools, which hold word lists and test phrases by the
// thousand.
var skip = map[string]bool{
	"appdata": true, "$recycle.bin": true, "system volume information": true,
	".git": true, ".svn": true, ".hg": true, "node_modules": true, "vendor": true, "bower_components": true,
	".venv": true, "venv": true, "__pycache__": true, "site-packages": true, ".tox": true,
	".gradle": true, ".dart_tool": true, ".pub-cache": true, ".m2": true, ".nuget": true, ".cargo": true,
	".cache": true, ".npm": true, ".yarn": true, ".pnpm-store": true, ".next": true, ".nuxt": true, ".expo": true,
	".vscode": true, ".idea": true, ".vs": true, ".tools": true,
}

const (
	Most  = 4 << 20 // the largest file read, in bytes
	Limit = 40000   // the most files read in one search
	Depth = 12      // how many folders deep a search goes
)

// Search reads the files under the folders given that can hold notes, and
// returns those that hold a run of recovery words. It calls note now and
// then with how many files it has read, and stops early when stop is
// closed. It only reads, and it leaves alone any file kept only in the
// cloud, as reading one would download it.
func Search(roots []string, stop <-chan struct{}, note func(read int)) model.PhraseSearch {
	result := model.PhraseSearch{When: time.Now(), Folders: roots}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			select {
			case <-stop:
				return errStopped
			default:
			}
			if err != nil {
				result.Locked++
				if d != nil && d.IsDir() && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			// A link or a junction leads somewhere else, perhaps back up the
			// tree. It is not followed: Windows reports it as neither a
			// file nor a folder.
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			if d.IsDir() {
				if path != root && (skip[strings.ToLower(d.Name())] || depth(root, path) > Depth) {
					return filepath.SkipDir
				}
				return nil
			}
			kind := strings.ToLower(filepath.Ext(d.Name()))
			if !kinds[kind] {
				return nil
			}
			// A document's pictures make the file large, while only its text
			// is read, so a document may be larger than a text file.
			most := int64(Most)
			if kind == ".docx" || kind == ".odt" {
				most *= 16
			}
			info, err := d.Info()
			switch {
			case err != nil:
				result.Locked++
				return nil
			case info.IsDir() || info.Size() == 0:
				return nil
			case onlyInCloud(info):
				result.Cloud++
				return nil
			case info.Size() > most:
				result.Big++
				return nil
			case result.Read >= Limit:
				result.Full = true
				return fs.SkipAll
			}
			text, err := Text(path)
			if err != nil {
				result.Locked++
				return nil
			}
			result.Read++
			if note != nil && result.Read%200 == 0 {
				note(result.Read)
			}
			if f, ok := judge(path, Find(text)); ok {
				result.Found = append(result.Found, f)
			}
			return nil
		})
		if errors.Is(err, errStopped) {
			result.Stopped = true
			break
		}
		if result.Full {
			break
		}
	}
	// The likeliest phrases first, then the rest, then the word lists.
	sort.SliceStable(result.Found, func(i, j int) bool { return rank(result.Found[i]) > rank(result.Found[j]) })
	return result
}

var errStopped = errors.New("the search was stopped")

// depth counts the folders between a root and a path below it.
func depth(root, path string) int {
	rest := strings.Trim(strings.TrimPrefix(path, root), `\/`)
	if rest == "" {
		return 0
	}
	return strings.Count(rest, string(filepath.Separator)) + 1
}

// judge sums up the runs found in one file.
func judge(path string, hits []Hit) (model.PhraseFile, bool) {
	if len(hits) == 0 {
		return model.PhraseFile{}, false
	}
	f := model.PhraseFile{Path: path, Runs: len(hits), List: true}
	for _, h := range hits {
		if len(f.Lines) < 20 {
			f.Lines = append(f.Lines, h.Line)
		}
		if h.List {
			continue
		}
		f.List = false
		f.Words = max(f.Words, h.Words)
		f.Phrase = max(f.Phrase, h.Phrase)
	}
	return f, true
}

func rank(f model.PhraseFile) int {
	switch {
	case f.Phrase > 0:
		return 2
	case !f.List:
		return 1
	}
	return 0
}

// Text reads a file as text: the words of a Word or OpenDocument file, a
// rich-text file without its codes, and plain text in UTF-8 or UTF-16. Each
// paragraph of a document is a line.
func Text(path string) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".docx":
		return document(path, wordFormat)
	case ".odt":
		return document(path, openFormat)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(filepath.Ext(path), ".rtf") {
		return richText(string(data)), nil
	}
	return decode(data), nil
}

// decode turns a file's bytes into text, minding a byte-order mark. A file
// with no mark that is mostly zero bytes in every other place is UTF-16, as
// Notepad's "Unicode" was.
func decode(data []byte) string {
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		return wide(data[2:], false)
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		return wide(data[2:], true)
	case len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF:
		return string(data[3:])
	}
	if len(data) >= 8 {
		odd, even := 0, 0
		for i := 0; i+1 < len(data); i += 2 {
			if data[i] == 0 {
				even++
			}
			if data[i+1] == 0 {
				odd++
			}
		}
		half := len(data) / 2
		switch {
		case odd > half*3/4 && even < half/8:
			return wide(data, false)
		case even > half*3/4 && odd < half/8:
			return wide(data, true)
		}
	}
	return string(data)
}

func wide(data []byte, big bool) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		if big {
			units[i] = uint16(data[2*i])<<8 | uint16(data[2*i+1])
		} else {
			units[i] = uint16(data[2*i+1])<<8 | uint16(data[2*i])
		}
	}
	return string(utf16.Decode(units))
}

// richText takes the codes out of a rich-text file, such as WordPad saves:
// \par and \line end a line, and other codes, such as \b for bold or \'e9
// for a letter, are not words of the text. The file's own line breaks are
// not breaks in the text.
func richText(raw string) string {
	raw = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(raw)
	raw = rtfBreaks.ReplaceAllString(raw, "\n")
	return rtfCodes.ReplaceAllString(raw, " ")
}

var (
	rtfBreaks = regexp.MustCompile(`\\(?:par|line)\b ?`)
	rtfCodes  = regexp.MustCompile(`\\[a-zA-Z]+-?\d* ?|\\'[0-9a-fA-F]{2}|\\.|[{}]`)
)

// format says where a kind of document keeps its text, and which of its
// marks end a paragraph and which stand for a space, such as a tab or a
// line break inside a paragraph.
type format struct {
	part         string
	ends, spaces *regexp.Regexp
}

var (
	wordFormat = format{"word/document.xml", regexp.MustCompile(`</w:p>|<w:p\b[^>]*/>`), regexp.MustCompile(`<w:(?:br|cr|tab)\b[^>]*>`)}
	openFormat = format{"content.xml", regexp.MustCompile(`</text:(?:p|h)>|<text:(?:p|h)\b[^>]*/>`), regexp.MustCompile(`<text:(?:line-break|tab|s)\b[^>]*>`)}
	markup     = regexp.MustCompile(`<[^>]*>`)
)

// document reads the words of a Word or OpenDocument file: the text of the
// part of the file that holds the body, with a line for each paragraph. The
// markup between the words is taken out without leaving a space, as Word
// can split one word over several pieces of it.
func document(path string, kind format) (string, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	for _, f := range archive.File {
		if f.Name != kind.part {
			continue
		}
		if f.UncompressedSize64 > Most*4 {
			return "", nil
		}
		r, err := f.Open()
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(io.LimitReader(r, Most*4))
		r.Close()
		if err != nil {
			return "", err
		}
		xml := strings.NewReplacer("\r", "", "\n", "").Replace(string(data))
		xml = kind.ends.ReplaceAllString(xml, "\n")
		xml = kind.spaces.ReplaceAllString(xml, " ")
		return markup.ReplaceAllString(xml, ""), nil
	}
	return "", nil
}
