package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type compileArgs struct {
	// Which compiler to use
	cc     string
	cFlags []string
	// Absolute input file name
	file string
	// Compiled ELF will be written here
	out io.Writer
	// Depfile will be written here if depName is not empty
	dep io.Writer
}

func compile(args compileArgs) error {
	cmd := exec.Command(args.cc, args.cFlags...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = args.out

	inputDir := filepath.Dir(args.file)
	cmd.Args = append(cmd.Args,
		"-c", args.file,
		"-o", "-",
		// Don't output inputDir into debug info
		"-fdebug-prefix-map="+inputDir+"=.",
		// We always want BTF to be generated, so enforce debug symbols
		"-g",
	)

	var (
		depRd, depWr *os.File
		err          error
	)
	if args.dep != nil {
		depRd, depWr, err = os.Pipe()
		if err != nil {
			return err
		}
		defer depRd.Close()
		defer depWr.Close()

		// This becomes /dev/fd/3
		cmd.ExtraFiles = append(cmd.ExtraFiles, depWr)
		cmd.Args = append(cmd.Args,
			// Output dependency information.
			"-MD",
			// Create phony targets so that deleting a dependency doesn't
			// break the build.
			"-MP",
			// Write it to our pipe
			"-MF/dev/fd/3",
		)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("can't execute %s: %s", args.cc, err)
	}

	if depRd != nil {
		// Close our copy of the write end so that Copy will terminate
		// when cc exits.
		depWr.Close()
		io.Copy(args.dep, depRd)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", args.cc, err)
	}

	return nil
}

func writeDepFile(mainFile string, dep []byte, out io.Writer) error {
	trimmed := bytes.TrimPrefix(dep, []byte("-: "))
	if len(trimmed) == len(dep) {
		return fmt.Errorf("can't replace main file name")
	}

	if _, err := io.WriteString(out, mainFile+": "); err != nil {
		return err
	}

	_, err := out.Write(trimmed)
	return err
}
