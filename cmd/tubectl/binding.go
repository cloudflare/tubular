package main

import (
	"fmt"
	"strconv"

	"code.cfops.it/sys/tubular/internal"
)

func bind(e env, args ...string) error {
	set := e.newFlagSet("bind")
	set.Usage = func() {
		fmt.Fprintf(set.Output(), "Usage: %s <label> <protocol> <ip[/mask]> <port>\n", set.Name())
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		return err
	}

	bind, err := bindingFromArgs(set.Args())
	if err != nil {
		return err
	}

	dp, err := e.openDispatcher()
	if err != nil {
		return err
	}
	defer dp.Close()

	return dp.AddBinding(bind)
}

func bindingFromArgs(args []string) (*internal.Binding, error) {
	if n := len(args); n != 4 {
		return nil, fmt.Errorf("expected label, protocol, ip and port but got %d arguments", n)
	}

	var proto internal.Protocol
	switch args[1] {
	case "udp":
		proto = internal.UDP
	case "tcp":
		proto = internal.TCP
	}

	port, err := strconv.ParseUint(args[3], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", err)
	}

	return internal.NewBinding(args[0], proto, args[2], uint16(port))
}
