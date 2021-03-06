package testutil

import (
	"fmt"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// EnterUnprivilegedMode drops all effective capabilities and enters a
// capabilities only environment.
//
// This means that privileged operations need to either change the effective
// capabilities of the current process, or execute a child process with a
// modified ambient capability set.
func EnterUnprivilegedMode() {
	const secbits = cap.SecbitNoRoot | cap.SecbitNoSetUIDFixup

	empty := cap.NewSet()
	if c, err := cap.GetProc().Cf(empty); err != nil {
		panic(err)
	} else if c == 0 {
		fmt.Println("Already unprivileged, not setting securebits")
		return
	}

	if err := secbits.Set(); err != nil {
		panic(fmt.Errorf("set securebits: %s", err.Error()))
	}

	// We need DAC_OVERRIDE since otherwise the go test runner is unable to
	// write out code coverage.
	ChangeEffectiveCaps(cap.DAC_OVERRIDE)
}

// ChangeEffectiveCaps modifies the effective capabilities to the given list
//
// The effective set will be empty if called without arguments.
//
// This function changes its behaviour based on whether it is run inside
// a WithCapabilities closure. In that case it sets the capabilities only
// for the current thread. Otherwise it changes the process' set.
func ChangeEffectiveCaps(caps ...cap.Value) error {
	set := cap.GetProc()
	if err := set.ClearFlag(cap.Effective); err != nil {
		return fmt.Errorf("clear effective: %s", err)
	}

	if len(caps) > 0 {
		err := set.SetFlag(cap.Effective, true, caps...)
		if err != nil {
			return fmt.Errorf("set effective: %s", err)
		}
	}

	if err := set.SetProc(); err != nil {
		return fmt.Errorf("set caps: %s", err)
	}

	return nil
}

// WithCapabilities raises the effective capabilities.
//
// Goroutines spawned from the passed function do not inherit the raised
// capabilities. Blocking in the passed function is allowed, but will block
// changes to the process' capability set.
//
// Passing an empty list of capabilities will invoke fn without any privileges.
func WithCapabilities(fn func() error, caps ...cap.Value) error {
	l := cap.FuncLauncher(func(interface{}) error {
		if err := ChangeEffectiveCaps(caps...); err != nil {
			return err
		}

		return fn()
	})

	_, err := l.Launch(nil)
	return err
}
