package log

import (
	"bytes"
	"fmt"
	"io"
	"log"
)

type Logger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	io.Writer
}

// StdLogger logs to a standard logger.
type StdLogger struct {
	*log.Logger
}

var _ Logger = (*StdLogger)(nil)

func NewStdLogger(w io.Writer) *StdLogger {
	return &StdLogger{log.New(w, "", 0)}
}

func (sl StdLogger) Log(args ...interface{}) {
	sl.Println(args...)
}

func (sl StdLogger) Logf(format string, args ...interface{}) {
	sl.Printf(format, args...)
}

func (sl StdLogger) Write(buf []byte) (int, error) {
	return sl.Writer().Write(buf)
}

// Buffer logs into memory.
//
// It's not safe for concurrent use.
type Buffer struct {
	bytes.Buffer
}

var _ Logger = (*Buffer)(nil)

func (b *Buffer) Log(args ...interface{}) {
	fmt.Fprintln(b, args...)
}

func (b *Buffer) Logf(format string, args ...interface{}) {
	fmt.Fprintf(b, format, args...)
}

var Discard Logger = discard{}

type discard struct{}

func (d discard) Log(args ...interface{})                 {}
func (d discard) Logf(format string, args ...interface{}) {}
func (d discard) Write(buf []byte) (int, error)           { return len(buf), nil }
