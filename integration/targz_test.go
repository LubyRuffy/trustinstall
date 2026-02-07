//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTarGzDirToWriter(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "a", "b"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "a", "b", "x.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "node_modules", ".bin"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "node_modules", ".bin", "tool"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write node_modules: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".git", "config"), []byte("secret"), 0o644); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	var buf bytes.Buffer
	if err := tarGzDirToWriter(&buf, tmp); err != nil {
		t.Fatalf("tarGzDirToWriter: %v", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	seen := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		name := filepath.ToSlash(strings.TrimPrefix(h.Name, "./"))
		if strings.HasPrefix(name, ".git/") || name == ".git/" {
			t.Fatalf("should not include .git: %q", name)
		}
		if strings.HasSuffix(name, "/") {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		seen[name] = b
	}

	if string(seen["a/b/x.txt"]) != "hello" {
		t.Fatalf("unexpected content: %q", string(seen["a/b/x.txt"]))
	}
	if _, ok := seen["node_modules/.bin/tool"]; ok {
		t.Fatalf("should not include node_modules")
	}
}
