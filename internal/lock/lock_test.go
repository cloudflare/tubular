package lock

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestExclusiveLock(t *testing.T) {
	dir, err := ioutil.TempDir("", "tubular")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	fh1, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fh1.Close()

	err = TryLockExclusive(fh1)
	if err != nil {
		t.Fatal("Can't lock file:", err)
	}

	fh2, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fh2.Close()

	err = TryLockExclusive(fh2)
	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("Expected EWOULDBLOCK, got", err)
	}

	fh1.Close()
	err = TryLockExclusive(fh2)
	if err != nil {
		t.Fatal("Closing fd doesn't release the lock:", err)
	}
}
