package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
)

func TestUsrMergeDest(t *testing.T) {
	type test struct {
		curPath  string
		curDest  string
		expected string
		err      error
	}

	tests := []test{
		{"bin/f1", "f2", "f2", nil},
		{"bin/f1", "../bin/f2", "f2", nil},
		{"bin/f1", "/usr/bin/f2", "f2", nil},
		{"bin/f1", "../../bin/f2", "f2", nil},
		{"bin/f1", "../usr/bin/f2", "f2", nil},
		{"bin/f1", "/etc/alternatives/f2", "../../etc/alternatives/f2", nil},
		{"bin/f1", "../../../wark/../usr/bin/f2", "f2", nil},
		{"bin/f1", "../opt/bin/f1", "../../opt/bin/f1", nil},
		{"usr/bin/f1", "/opt/bin/f1", "../../opt/bin/f1", nil},
		{"usr/bin/f1", "../bin/f2", "f2", nil},
		{"sbin/f1", "../bin/f2", "f2", nil},
		{"bin/f1", "../usr/local/bin/f1", "../local/bin/f1", nil},
		{"bin/f1", "/usr/local/bin/f1", "../local/bin/f1", nil},
	}

	for _, v := range tests {
		newDest, errFound := usrMergeDest(v.curPath, v.curDest, "/home/melange/output")
		if errFound != nil {
			if errFound == v.err {
				continue
			}
			if v.err == nil {
				t.Errorf("Unexpected non-nil err value received. %v -> (%s, %v)", v, newDest, errFound)
			} else if v.err != errFound {
				t.Errorf("Unexpected err value received. %v -> (%s, %v)", v, newDest, errFound)
			}
			continue
		} else {
			if newDest != v.expected {
				t.Errorf("Expected %s, found %s. %v", v.expected, newDest, v)
			}
		}
	}
}

var testTrees = []struct{ input, expected []FSEntry }{
	{
		input: []FSEntry{
			{Path: "bin", Type: "dir"},
		},
		expected: []FSEntry{},
	},
	{
		input: []FSEntry{
			{Path: "bin", Type: "dir"},
			{Path: "bin/busybox", Type: "file"},
			{Path: "bin/sh", Type: "slink", Target: "busybox"},
			{Path: "sbin", Type: "dir"},
			{Path: "sbin/chroot", Type: "slink", Target: "../bin/busybox"},
		},
		expected: []FSEntry{
			{Path: "usr", Type: "dir"},
			{Path: "usr/bin", Type: "dir"},
			{Path: "usr/bin/busybox", Type: "file"},
			{Path: "usr/bin/sh", Type: "slink", Target: "busybox"},
			{Path: "usr/bin/chroot", Type: "slink", Target: "busybox"},
		},
	},
}

func TestMerge(t *testing.T) {
	for _, v := range testTrees {
		sort.Slice(v.expected, func(i, j int) bool { return v.expected[i].Path < v.expected[j].Path })
		tmpd, err := os.MkdirTemp("", "usrmergetest")
		if err != nil {
			t.Errorf("failed creating tmpdir")
			continue
		}

		defer os.RemoveAll(tmpd)

		if err = populateFromDescription(tmpd, v.input); err != nil {
			t.Errorf("failed to populate dir: %v", err)
			continue
		}

		err = usrSbinMergeRoot(tmpd)
		if err != nil {
			t.Errorf("filed merge %v", err)
			continue
		}

		err = compareFileSystem(tmpd, FSDesc{v.expected})
		if err != nil {
			t.Errorf("Different results than expected: %v", err)
		}
	}
}

type FSEntry struct {
	Path    string `yaml:"path"`
	Type    string `yaml:"type"`
	Content string `yaml:"content,omitempty"`
	Target  string `yaml:"target,omitempty"`
}

type FSDesc struct {
	Entries []FSEntry `yaml:"ents"`
}

func createEntry(baseDir string, entry FSEntry) error {
	fullPath := filepath.Join(baseDir, entry.Path)
	switch entry.Type {
	case "dir":
		return os.MkdirAll(fullPath, 0755)
	case "file":
		return ioutil.WriteFile(fullPath, []byte(entry.Content), 0644)
	case "slink":
		return os.Symlink(entry.Target, fullPath)
	case "hlink":
		return os.Link(filepath.Join(baseDir, entry.Target), fullPath)
	default:
		return fmt.Errorf("unsupported type: %s", entry.Type)
	}
}

func populateFromDescription(baseDir string, fsDescs []FSEntry) error {
	for _, entry := range fsDescs {
		if err := createEntry(baseDir, entry); err != nil {
			return err
		}
	}
	return nil
}

func scanDirectory(baseDir string) (FSDesc, error) {
	var fsDesc FSDesc = FSDesc{Entries: []FSEntry{}}
	inodeMap := make(map[uint64]string)

	var paths []string
	filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			paths = append(paths, path)
		}
		return nil
	})

	sort.Strings(paths)

	for _, path := range paths {
		if path == baseDir {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fsDesc, err
		}

		relPath, _ := filepath.Rel(baseDir, path)
		if relPath == "." {
			continue
		}

		entry := FSEntry{Path: relPath}
		switch {
		case info.IsDir():
			entry.Type = "dir"
		case info.Mode()&os.ModeSymlink != 0:
			target, _ := os.Readlink(path)
			entry.Type = "slink"
			entry.Target = target
		case info.Mode().IsRegular():
			var stat syscall.Stat_t
			if err := syscall.Stat(path, &stat); err == nil {
				inode := stat.Ino
				if existingPath, found := inodeMap[inode]; found {
					entry.Type = "hlink"
					entry.Target = existingPath
				} else {
					inodeMap[inode] = relPath
					entry.Type = "file"
					content, _ := ioutil.ReadFile(path)
					entry.Content = string(content)
				}
			}
		}
		fsDesc.Entries = append(fsDesc.Entries, entry)
	}

	return fsDesc, nil
}

func compareFileSystem(baseDir string, expectedFS FSDesc) error {
	foundFSD, err := scanDirectory(baseDir)
	if err != nil {
		return err
	}

	expectedJSON, _ := json.MarshalIndent(expectedFS, "", "  ")
	actualJSON, _ := json.MarshalIndent(foundFSD, "", "  ")

	if !bytes.Equal(expectedJSON, actualJSON) {
		fmt.Println("Filesystem does not match expected structure!")
		fmt.Println("Expected:")
		fmt.Println(string(expectedJSON))
		fmt.Println("Actual:")
		fmt.Println(string(actualJSON))
		return fmt.Errorf("mismatch detected")
	}

	return nil
}
