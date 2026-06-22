package conformance_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/murmuration-protocol/murmur-go/conformance"
)

// vectorsDir resolves the conformance-vector corpus. It honours MURMUR_VECTORS
// (used by CI, where the spec repo is a separate checkout) and otherwise
// defaults to the sibling spec repo, ../../spec/vectors relative to this source
// file, so a local `go test ./...` finds it from any working directory.
func vectorsDir(t *testing.T) string {
	if d := os.Getenv("MURMUR_VECTORS"); d != "" {
		return d
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the conformance source path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "spec", "vectors")
}

func TestVectors(t *testing.T) {
	dir := vectorsDir(t)
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("vectors not found at %s (set MURMUR_VECTORS): %v", dir, err)
	}
	files, err := conformance.Files(dir)
	if err != nil {
		t.Fatalf("globbing vectors: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no vectors found under %s", dir)
	}
	for _, path := range files {
		rel, _ := filepath.Rel(dir, path)
		t.Run(rel, func(t *testing.T) {
			v, err := conformance.Load(path)
			if err != nil {
				t.Fatalf("loading: %v", err)
			}
			if err := v.Check(); err != nil {
				t.Errorf("%s: %v", v.Kind, err)
			}
		})
	}
}
