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

	if set.NArg() < 4 {
		set.Usage()
		return fmt.Errorf("missing arguments")
	}

	bdg, err := bindingFromArgs(set.Arg(1), set.Arg(2), set.Arg(3))
	if err != nil {
		return err
	}

	dp, err := e.openDispatcher()
	if err != nil {
		return err
	}
	defer dp.Close()

	return dp.AddBinding(set.Arg(0), bdg)
}

func bindingFromArgs(protoStr, prefixStr, portStr string) (*internal.Binding, error) {
	var proto internal.Protocol
	switch protoStr {
	case "udp":
		proto = internal.UDP
	case "tcp":
		proto = internal.TCP
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", err)
	}

	return internal.NewBinding(proto, prefixStr, uint16(port))
}
