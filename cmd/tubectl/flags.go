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
	args        []string
	Description interface{}
}

func newFlagSet(output io.Writer, name string, args ...string) *flagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(output)

	fs := &flagSet{
		*set,
		args,
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

func (fs *flagSet) PrintCommand() {
	o := fs.Output()

	var args string
	if len(fs.args) > 0 {
		args = fmt.Sprintf("<%s>", strings.Join(fs.args, "> <"))
	}

	fmt.Fprintf(o, "Usage: tubectl %s %s\n\n", fs.Name(), args)
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
	removeLeadingTabs.ReplaceAllLiteralString(s, "\n")
	return strings.TrimSpace(s)
}
