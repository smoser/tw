package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	bin     = Move{src: "bin", dest: "usr/bin"}
	sbin    = Move{src: "sbin", dest: "usr/bin"}
	usrSbin = Move{src: "usr/sbin", dest: "usr/bin"}
)

func main() {
	moves := []Move{}

	flag.BoolFunc("bin", "move bin/ to usr/bin",
		func(s string) error { moves = append(moves, bin); return nil })
	flag.BoolFunc("sbin", "move sbin/ to usr/bin",
		func(s string) error { moves = append(moves, sbin); return nil })
	flag.BoolFunc("usr-sbin", "move usr-sbin to usr/bin",
		func(s string) error { moves = append(moves, usrSbin); return nil })
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Must give a destdir\n")
		os.Exit(1)
	}

	destdir := flag.Arg(0)

	if len(moves) == 0 {
		fmt.Fprintf(os.Stderr, "Must give at least one of --bin, --sbin, --usr-sbin\n")
		os.Exit(1)
	}

	err := mergeRoot(destdir, moves)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mergeRoot(%s, %v) returned err: %v", destdir, moves, err)
		os.Exit(1)
	}

	fmt.Printf("merged %s\n", destdir)
	return
}
