package main

import (
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type flagSet struct {
	flag.FlagSet
	args         []string
	optionalArgs []string
	Description  interface{}
}

// newFlagSet creates a flag set for a command with the given name.
//
// args contains both required an optional arguments, separated by the special
// string "--".
func newFlagSet(output io.Writer, name string, args ...string) *flagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(output)

	var optionalArgs []string
	for i, arg := range args {
		if arg == "--" {
			optionalArgs = args[i+1:]
			args = args[:i]
			break
		}
	}

	fs := &flagSet{
		*set,
		args,
		optionalArgs,
		nil,
	}

	fs.Usage = func() {
		fs.PrintCommand()
		switch v := fs.Description.(type) {
		case func():
			v()
		case string:
			io.WriteString(fs.Output(), trimLeadingTabsAndSpace(v)+"\n\n")
		case nil:
			// Nothing to do
		default:
			panic("unsupported type")
		}
		fs.PrintDefaults()
	}

	return fs
}

func (fs *flagSet) Parse(args []string) error {
	if err := fs.FlagSet.Parse(args); err != nil {
		return err
	}

	minArgs := len(fs.args)
	maxArgs := minArgs + len(fs.optionalArgs)
	if n := fs.NArg(); n >= minArgs && n <= maxArgs {
		return nil
	}

	fs.PrintCommand()
	return errBadArg
}

func (fs *flagSet) PrintCommand() {
	o := fs.Output()

	var args string
	if len(fs.args) > 0 {
		args = fmt.Sprintf(" <%s>", strings.Join(fs.args, "> <"))
	}
	if len(fs.optionalArgs) > 0 {
		args += fmt.Sprintf(" [<%s>]", strings.Join(fs.optionalArgs, ">] [<"))
	}

	fmt.Fprintf(o, "Usage: tubectl %s%s\n\n", fs.Name(), args)
}

func (fs *flagSet) Printf(format string, args ...interface{}) {
	usage := fmt.Sprintf(format, args...)
	io.WriteString(fs.Output(), trimLeadingTabsAndSpace(usage)+"\n")
}

var removeLeadingTabs = regexp.MustCompile(`\n\t+`)

// trimLeadingTabsAndSpace removes leading tabs from anywhere in the given
// string, and whitespace from either end.
//
// This allows using arbitrary alignment in source code raw strings without
// messing up the console output.
func trimLeadingTabsAndSpace(s string) string {
	s = removeLeadingTabs.ReplaceAllLiteralString(s, "\n")
	return strings.TrimSpace(s)
}
