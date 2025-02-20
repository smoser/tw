package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Move struct{ src, dest string }

// resolveUnderRoot resolves dest relative to source and ensures the resulting path stays within root.
// returns full cleaned paths to source and dest
// - If source is not absolute, it is treated as relative to root.
// - If dest is absolute, it is reinterpreted as relative to root (its leading separator is removed).
// - Any upward traversals (e.g. "../") that would escape root are clamped.
func resolveUnderRoot(source, dest, root string) (string, string, error) {
	// Ensure root is an absolute, clean path.
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve root path: %w", err)
	}

	// If source is not absolute, treat it as relative to root.
	if !filepath.IsAbs(source) {
		source = filepath.Join(root, source)
	}
	source = filepath.Clean(source)

	var candidate string
	if filepath.IsAbs(dest) {
		// If dest is absolute, strip the leading separator and treat it as relative to root.
		dest = filepath.Clean(dest)
		dest = strings.TrimPrefix(dest, string(filepath.Separator))
		candidate = filepath.Join(root, dest)
	} else {
		// Otherwise, dest is relative to source.
		candidate = filepath.Join(filepath.Dir(source), dest)
	}
	candidate = filepath.Clean(candidate)

	// At this point, candidate might be outside of root if dest contained "../" segments.
	// We compute the relative path from root to candidate.
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", "", fmt.Errorf("unable to compute relative path: %w", err)
	}

	// Split the relative path into its segments.
	parts := strings.Split(rel, string(filepath.Separator))
	// Remove any leading ".." segments, effectively clamping the upward moves.
	safeParts := []string{}
	for _, part := range parts {
		if part == ".." {
			// Skip any upward traversal that would leave root.
			continue
		}
		// Also ignore empty parts (which may occur if rel is ".")
		if part != "" && part != "." {
			safeParts = append(safeParts, part)
		}
	}

	// Reconstruct the final path as root joined with the safe relative parts.
	finalPath := filepath.Join(append([]string{root}, safeParts...)...)
	finalPath = filepath.Clean(finalPath)

	// Ensure finalPath is absolute.
	finalPath, err = filepath.Abs(finalPath)
	if err != nil {
		return "", "", fmt.Errorf("unable to obtain absolute path: %w", err)
	}

	return source, finalPath, nil
}

func newLinkDest(curSrc, curDest, rootPath, newDirPath string, equivs []string) (string, error) {
	rootPath, err := filepath.Abs(filepath.Clean(rootPath))
	if err != nil {
		return "", fmt.Errorf("failed to resolve root path: %w", err)
	}

	_, dest, err := resolveUnderRoot(curSrc, curDest, rootPath)
	if err != nil {
		return "", err
	}

	if dest == rootPath {
		r, err := filepath.Rel(newDirPath, "")
		if err != nil {
			return "", err
		}
		return filepath.Clean(r), nil
	}

	// src and dest are both under rootPath
	relDest := strings.TrimPrefix(dest, rootPath+string(filepath.Separator))
	relDestDir := filepath.Dir(relDest)
	// fmt.Printf("reldest=%s newDirPath=%s relDestDir=%s\n", relDest, newDirPath, relDestDir)
	if relDestDir == newDirPath || slices.Contains(equivs, relDestDir) {
		return filepath.Base(curDest), nil
	}

	r, err := filepath.Rel(newDirPath, filepath.Join(relDestDir, filepath.Base(curDest)))
	if err != nil {
		return "", err
	}
	return r, nil
}

func usrSbinMergeRoot(rootPath string) error {
	return mergeRoot(rootPath,
		[]Move{
			{"bin", "usr/bin"},
			{"sbin", "usr/bin"},
			{"usr/sbin", "usr/bin"},
		})
}

func mergeRoot(rootPath string, moves []Move) error {
	var err error

	equivs := []string{}
	for _, k := range moves {
		equivs = append(equivs, k.src)
	}

	rpIn := rootPath
	if rootPath, err = filepath.Abs(rootPath); err != nil {
		return fmt.Errorf("failed to find absolute path to %s", rpIn)
	}
	rootPath = filepath.Clean(rootPath)

	for _, m := range moves {
		dest := filepath.Join(rootPath, m.dest)
		src := filepath.Join(rootPath, m.src)
		srcInfo, err := os.Lstat(src)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		} else if srcInfo.Mode()&os.ModeSymlink != 0 {
			srcDest, err := os.Readlink(src)
			if err != nil {
				return fmt.Errorf("failed Readlink(%s): %v", src, err)
			}
			if srcDest == m.dest {
				continue
			}
			return fmt.Errorf("%s existed as a symlink not to %s. it pointed to %s", m.src, m.dest, srcDest)
		}

		if err := os.MkdirAll(dest, 0755); err != nil && !os.IsExist(err) {
			return err
		}

		entries, err := os.ReadDir(src)
		if err != nil {
			return fmt.Errorf("Failed to open %s for reading: %v", src, err)
		}

		for _, dirEnt := range entries {
			fInfo, err := dirEnt.Info()
			if err != nil {
				return fmt.Errorf("failed reading file info for %s: %v", dirEnt.Name(), err)
			}

			fpSrc := filepath.Join(src, dirEnt.Name())
			fpDest := filepath.Join(dest, dirEnt.Name())
			relSrc := filepath.Join(m.src, dirEnt.Name())
			relDest := filepath.Join(m.dest, dirEnt.Name())

			if fInfo.Mode()&os.ModeSymlink == 0 {
				fmt.Fprintf(os.Stderr, "rename %s -> %s\n", relSrc, relDest)
				if err := os.Rename(fpSrc, fpDest); err != nil {
					return fmt.Errorf("failed renaming %s -> %s: %v",
						filepath.Join(m.src, dirEnt.Name()), filepath.Join(m.dest, dirEnt.Name()), err)
				}
			} else {
				curTarget, err := os.Readlink(fpSrc)
				if err != nil {
					return fmt.Errorf("failed reading link for %s: %v", fpSrc, err)
				}

				newDest, err := newLinkDest(fpSrc, curTarget, rootPath, "usr/bin", equivs)
				if err != nil {
					return err
				}

				fmt.Fprintf(os.Stderr, "relink %s -> %s [old=%s new=%s]\n", relSrc, relDest, curTarget, newDest)

				if err := os.Symlink(newDest, fpDest); err != nil {
					return err
				}

				if err := os.Remove(fpSrc); err != nil {
					return err
				}
			}
		}

		if err := os.Remove(src); err != nil {
			filepath.WalkDir(src, func(path string, _ os.DirEntry, err error) error { fmt.Printf("%s\n", path); return nil })
			return fmt.Errorf("failed to remove %s after moves: %v", m.src, err)
		}

		entries, err = os.ReadDir(dest)
		if len(entries) == 0 {
			if err := os.Remove(dest); err != nil {
				return fmt.Errorf("failed removing empty usr/bin (%s) dir: %v", dest, err)
			}
		}

		usr := filepath.Join(rootPath, "usr")
		entries, err = os.ReadDir(usr)
		if len(entries) == 0 {
			if err := os.Remove(usr); err != nil {
				return fmt.Errorf("failed removing empty usr dir: %v", err)
			}
		}
	}

	return nil
}

func usrMergeDest(curPath, curDest, rootPath string) (string, error) {
	return newLinkDest(curPath, curDest, rootPath, "usr/bin", []string{"bin"})
}
