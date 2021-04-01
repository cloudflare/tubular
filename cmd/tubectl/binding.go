package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"code.cfops.it/sys/tubular/internal"
)

func bind(e *env, args ...string) error {
	set := e.newFlagSet("bind", `<label> <protocol> <ip[/mask]> <port>

Bind a given prefix, port and protocol to a label.
`)
	if err := set.Parse(args); err != nil {
		return err
	}

	bind, err := bindingFromArgs(set.Args())
	if err != nil {
		return err
	}

	dp, err := e.openDispatcher(false)
	if err != nil {
		return err
	}
	defer dp.Close()

	return dp.AddBinding(bind)
}

func unbind(e *env, args ...string) error {
	set := e.newFlagSet("unbind", `<label> <protocol> <ip[/mask]> <port>

Remove a previously created binding.
`)
	if err := set.Parse(args); err != nil {
		return err
	}

	bind, err := bindingFromArgs(set.Args())
	if err != nil {
		return err
	}

	dp, err := e.openDispatcher(false)
	if err != nil {
		return err
	}
	defer dp.Close()

	if err := dp.RemoveBinding(bind); err != nil {
		return err
	}

	e.stdout.Log("Removed", bind)
	return nil
}

func bindingFromArgs(args []string) (*internal.Binding, error) {
	if n := len(args); n != 4 {
		return nil, fmt.Errorf("expected label, protocol, ip/prefix and port but got %d arguments", n)
	}

	var proto internal.Protocol
	switch args[1] {
	case "udp":
		proto = internal.UDP
	case "tcp":
		proto = internal.TCP
	default:
		return nil, fmt.Errorf("expected proto udp or tcp, got: %s", args[1])
	}

	port, err := strconv.ParseUint(args[3], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", err)
	}

	return internal.NewBinding(args[0], proto, args[2], uint16(port))
}

func loadBindings(e *env, args ...string) error {
	set := e.newFlagSet("load-bindings", `<file>

Load a set of bindings from a JSON formatted file and replace the currently
active bindings with the ones from the file.

Example:

  $ jq . bindings.json
  {
    "bindings": [
      {
        "label": "foo",
        "prefix": "127.0.0.1"
      },
      {
        "label": "bar",
        "prefix": "::1/64"
      }
    ]
  }
  $ tubectl load-bindings bindings.json
  …
  $ tubectl list
  …
  Bindings:
   protocol       prefix port label
        tcp 127.0.0.1/32    0   foo
        tcp        ::/64    0   bar
        udp 127.0.0.1/32    0   foo
        udp        ::/64    0   bar
  …

`)
	if err := set.Parse(args); err != nil {
		return err
	}

	if set.NArg() != 1 {
		set.Usage()
		return errBadArg
	}

	file, err := os.Open(set.Arg(0))
	if err != nil {
		return err
	}
	defer file.Close()

	var config struct {
		Bindings []struct {
			Label  string          `json:"label"`
			Prefix *internal.IPNet `json:"prefix"`
		} `json:"bindings"`
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("%s: %s", file.Name(), err)
	}

	var bindings []*internal.Binding
	for _, bind := range config.Bindings {
		bindings = append(bindings,
			&internal.Binding{
				Label:    bind.Label,
				Prefix:   bind.Prefix,
				Protocol: internal.TCP,
				Port:     0,
			},
			&internal.Binding{
				Label:    bind.Label,
				Prefix:   bind.Prefix,
				Protocol: internal.UDP,
				Port:     0,
			},
		)
	}

	dp, err := e.openDispatcher(false)
	if err != nil {
		return err
	}
	defer dp.Close()

	_, err = dp.ReplaceBindings(bindings)
	return err
}
