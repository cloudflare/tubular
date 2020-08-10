package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const helpText = `Usage: %[1]s [options] <ident> <source file> [-- <C flags>]

ident is used as the stem of all generated Go types and functions, and
must be a valid Go identifier.

source is a single C file that is compiled using the specified compiler
(usually some version of clang).

You can pass options to the compiler by appending them after a '--' argument
or by supplying -cflags. Flags passed as arguments take precedence
over flags passed via -cflags. Additionally, the program expands quotation
marks in -cflags. This means that -cflags 'foo "bar baz"' is passed to the
compiler as two arguments "foo" and "bar baz".

The program expects GOPACKAGE to be set in the environment, and should be invoked
via go generate. The generated files are written to the current directory.

Options:

`

func run(stdout io.Writer, pkg, outputDir string, args []string) (err error) {
	removeOnError := func(f *os.File) {
		if err != nil {
			os.Remove(f.Name())
		}
		f.Close()
	}

	var (
		fs           = flag.NewFlagSet("bpf2go", flag.ContinueOnError)
		flagCC       = fs.String("cc", "clang", "`binary` used to compile C to BPF")
		flagCFlags   = fs.String("cflags", "", "flags passed to the compiler, may contain quoted arguments")
		flagTags     = fs.String("tags", "", "list of Go build tags to include in generated files")
		flagTarget   = fs.String("target", "", "clang target to compile for (bpf, bpfel, bpfeb)")
		flagMakeBase = fs.String("makebase", "", "write make compatible depinfo files relative to `directory`")
	)

	fs.SetOutput(stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), helpText, fs.Name())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if pkg == "" {
		return errors.New("missing package, are you running via go generate?")
	}

	if *flagCC == "" {
		return errors.New("no compiler specified")
	}

	args, cFlags := splitCFlagsFromArgs(fs.Args())

	if *flagCFlags != "" {
		splitCFlags, err := splitArguments(*flagCFlags)
		if err != nil {
			return err
		}

		// Command line arguments take precedence over C flags
		// from the flag.
		cFlags = append(splitCFlags, cFlags...)
	}

	if len(args) < 2 {
		return errors.New("expected at least two arguments")
	}

	ident := args[0]
	if !token.IsIdentifier(ident) {
		return fmt.Errorf("%q is not a valid identifier", ident)
	}

	inputDir, inputFile, err := splitPathAbs(args[1])
	if err != nil {
		return err
	}

	var makeBase string
	if *flagMakeBase != "" {
		makeBase, err = filepath.Abs(*flagMakeBase)
		if err != nil {
			return err
		}
	}

	if strings.ContainsRune(*flagTags, '\n') {
		return fmt.Errorf("-tags mustn't contain new line characters")
	}

	tagsByTarget := map[string]string{
		"bpf":   "",
		"bpfel": "386 amd64 amd64p32 arm arm64 mipsle mips64le mips64p32le ppc64le",
		"bpfeb": "armbe arm64be mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64",
	}

	var targets []string
	if *flagTarget != "" {
		if _, ok := tagsByTarget[*flagTarget]; !ok {
			return fmt.Errorf("unsupported target %q", *flagTarget)
		}
		targets = []string{*flagTarget}
	} else {
		targets = []string{"bpfel", "bpfeb"}
	}

	cFlags = cFlags[:len(cFlags):len(cFlags)]
	for _, target := range targets {
		var obj, dep bytes.Buffer
		err = compile(compileArgs{
			cc:     *flagCC,
			cFlags: append(cFlags, "-target", target),
			file:   inputDir + inputFile,
			out:    &obj,
			dep:    &dep,
		})

		if err != nil {
			return err
		}

		// Write out compiled BPF
		objFileName := fmt.Sprintf("%s_%s.o", stripExtension(inputFile), target)
		objFileName = filepath.Join(inputDir, objFileName)
		objFile, err := os.Create(objFileName)
		if err != nil {
			return err
		}
		defer removeOnError(objFile)

		if _, err := objFile.Write(obj.Bytes()); err != nil {
			return fmt.Errorf("can't write %s: %s", objFileName, err)
		}

		fmt.Fprintln(stdout, "Wrote", objFileName)

		// Write out generated go
		goFileName := fmt.Sprintf("%s_%s.go", strings.ToLower(ident), target)
		goFileName = filepath.Join(outputDir, goFileName)
		goFile, err := os.Create(goFileName)
		if err != nil {
			return err
		}
		defer removeOnError(goFile)

		var tags []string
		if targetTags := tagsByTarget[target]; targetTags != "" {
			tags = append(tags, targetTags)
		}
		if *flagTags != "" {
			tags = append(tags, *flagTags)
		}

		err = writeCommon(writeArgs{
			pkg:   pkg,
			ident: ident,
			tags:  tags,
			obj:   obj.Bytes(),
			out:   goFile,
		})
		if err != nil {
			return fmt.Errorf("can't write %s: %s", goFileName, err)
		}

		fmt.Fprintln(stdout, "Wrote", goFileName)

		if makeBase == "" {
			continue
		}

		depFileName := goFileName + ".d"
		depFile, err := os.Create(depFileName)
		if err != nil {
			return err
		}
		defer removeOnError(depFile)

		mainFile, err := filepath.Rel(makeBase, goFileName)
		if err != nil {
			return err
		}

		if err := writeDepFile(mainFile, dep.Bytes(), depFile); err != nil {
			return fmt.Errorf("can't write %s: %s", depFileName, err)
		}

		fmt.Fprintln(stdout, "Wrote", depFileName)
	}

	return nil
}

func main() {
	outputDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if err := run(os.Stdout, os.Getenv("GOPACKAGE"), outputDir, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}