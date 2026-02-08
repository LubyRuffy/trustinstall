//go:build integration || all_platform

package integration

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func tarGzDirToWriter(w io.Writer, root string) error {
	root = filepath.Clean(root)
	st, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("not a dir: %s", root)
	}

	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		// Skip frontend deps; they are huge and contain symlinks that often fail to extract in minimal guests.
		if d.IsDir() && filepath.Base(path) == "node_modules" {
			return filepath.SkipDir
		}
		if strings.Contains("/"+rel+"/", "/node_modules/") {
			return nil
		}

		// Skip VCS metadata to keep uploads smaller and deterministic.
		if d.IsDir() && rel == ".git" {
			return filepath.SkipDir
		}
		if strings.HasPrefix(rel, ".git/") {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			// Preserve symlink target; otherwise tar may create an empty link which breaks extraction.
			if target, err := os.Readlink(path); err == nil {
				link = target
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = rel
		if info.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
			hdr.Name += "/"
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, f)
			_ = f.Close()
			if copyErr != nil {
				return copyErr
			}
		}
		return nil
	})
}
