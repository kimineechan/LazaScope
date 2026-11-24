package virustotal

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// LazaScope reaches the internet in one place only: this package, when a
// person has set up a VirusTotal key. No other part of the program may
// import Go's network packages, and nothing may start other programs except
// the check that plants and removes test items. Tests are left out: they
// talk to stand-ins on this PC.
func TestNothingElseReachesTheNetwork(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	network := map[string]bool{"net": true, "net/http": true, "net/url": true, "crypto/tls": true, "net/smtp": true, "net/rpc": true}
	here := filepath.Join(root, "internal", "virustotal")
	verify := filepath.Join(root, "cmd", "verify")
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "dist" || d.Name() == ".git" || strings.HasPrefix(d.Name(), ".")) && path != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, spec := range file.Imports {
			name, _ := strconv.Unquote(spec.Path.Value)
			if network[name] && filepath.Dir(path) != here {
				t.Errorf("%s imports %s: only internal/virustotal may reach the network", path, name)
			}
			if name == "os/exec" && filepath.Dir(path) != verify {
				t.Errorf("%s imports os/exec: LazaScope starts no other programs", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 50 {
		t.Errorf("only %d source files were checked; the walk went wrong", checked)
	}
}
