package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"code.cfops.it/sys/tubular/internal"
	"inet.af/netaddr"
)

func bindings(e *env, args ...string) error {
	set := e.newFlagSet("bindings", "--", "protocol", "prefix[/mask]", "port")
	set.Description = `
		List bindings which match certain criteria.

		Examples:
		  $ tubectl bindings
		  $ tubectl bindings any 127.0.0.0/8
		  $ tubectl bindings udp ::1 443`
	if err := set.Parse(args); err != nil {
		return err
	}

	var proto internal.Protocol
	if f := set.Arg(0); set.NArg() >= 1 && f != "any" {
		if err := proto.UnmarshalText([]byte(f)); err != nil {
			return fmt.Errorf("parse protocol: %w", err)
		}
	}

	var prefix netaddr.IPPrefix
	var err error
	if set.NArg() >= 2 {
		prefix, err = internal.ParsePrefix(set.Arg(1))
		if err != nil {
			return err
		}
	}

	var port uint16
	if set.NArg() >= 3 {
		port64, err := strconv.ParseUint(set.Arg(2), 10, 16)
		if err != nil {
			return fmt.Errorf("port %q: %w", set.Arg(2), err)
		}
		port = uint16(port64)
	}

	var bindings internal.Bindings
	{
		dp, err := e.openDispatcher(true)
		if err != nil {
			return fmt.Errorf("open dispatcher: %w", err)
		}
		defer dp.Close()

		bindings, err = dp.Bindings()
		if err != nil {
			return fmt.Errorf("get bindings: %s", err)
		}

		dp.Close()
	}

	var filtered internal.Bindings
	for _, bind := range bindings {
		if proto != 0 && bind.Protocol != proto {
			continue
		}

		if !prefix.IsZero() && !prefix.Overlaps(bind.Prefix) {
			continue
		}

		if port != 0 && bind.Port != 0 && bind.Port != port {
			continue
		}

		filtered = append(filtered, bind)
	}
	bindings = filtered

	if len(bindings) == 0 {
		e.stdout.Log("no bindings matched")
		return nil
	}

	e.stdout.Log("Bindings:")
	w := tabwriter.NewWriter(e.stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
	return printBindings(w, bindings)
}

func bind(e *env, args ...string) error {
	set := e.newFlagSet("bind", "label", "protocol", "ip[/mask]", "port")
	set.Description = `
		Bind a given prefix, port and protocol to a label.

		Examples:
		  $ tubectl bind foo udp 127.0.0.1 0
		  $ tubectl bind bar tcp 127.0.0.0/24 80`

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

	if err := dp.AddBinding(bind); err != nil {
		return err
	}

	e.stdout.Logf("bound %s", bind)
	return nil
}

func unbind(e *env, args ...string) error {
	set := e.newFlagSet("unbind", "label", "protocol", "ip[/mask]", "port")
	set.Description = "Remove a previously created binding."
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

type bindingJSON struct {
	Label  string           `json:"label"`
	Prefix netaddr.IPPrefix `json:"prefix"`
	Port   *uint16          `json:"port"`
}

type configJSON struct {
	Bindings []bindingJSON `json:"bindings"`
}

func loadBindings(e *env, args ...string) error {
	set := newFlagSet(e.stderr, "load-bindings", "file")
	set.Description = func() {
		port := uint16(80)
		example := configJSON{
			Bindings: []bindingJSON{
				{"foo", netaddr.MustParseIPPrefix("127.0.0.1/32"), &port},
			},
		}

		out, _ := json.MarshalIndent(example, "    ", "    ")

		set.Printf(
			`Load a set of bindings from a JSON formatted file and replace
			the currently active bindings with the ones from the file.

			The format is:

			    %s`,
			string(out),
		)
	}

	if err := set.Parse(args); err != nil {
		return err
	}

	if set.NArg() != 1 {
		set.Usage()
		return errBadArg
	}

	bindings, err := loadConfig(set.Arg(0))
	if err != nil {
		return err
	}

	dp, err := e.openDispatcher(false)
	if err != nil {
		return err
	}
	defer dp.Close()

	added, removed, err := dp.ReplaceBindings(bindings)
	if err != nil {
		return err
	}

	for _, bind := range added {
		e.stdout.Log("added", bind)
	}
	for _, bind := range removed {
		e.stdout.Log("removed", bind)
	}

	return nil
}

func loadConfig(path string) (internal.Bindings, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config configJSON
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("%s: %s", file.Name(), err)
	}

	var bindings internal.Bindings
	for _, bind := range config.Bindings {
		if bind.Port == nil {
			return nil, fmt.Errorf("binding in json is missing port: %v", bind)
		}

		bindings = append(bindings,
			&internal.Binding{
				Label:    bind.Label,
				Prefix:   bind.Prefix.Masked(),
				Protocol: internal.TCP,
				Port:     *bind.Port,
			},
			&internal.Binding{
				Label:    bind.Label,
				Prefix:   bind.Prefix.Masked(),
				Protocol: internal.UDP,
				Port:     *bind.Port,
			},
		)
	}

	return bindings, nil
}
