package main

import (
	"code.cfops.it/sys/tubular/internal"
)

func unregister(e *env, args ...string) error {
	set := e.newFlagSet("unregister", "label", "domain", "proto")
	set.Description = `
		Removes the socket mapping for the given label, domain and protocol.

		Examples:
		  $ tubectl unregister foo ipv4 udp
		  $ tubectl unregister bar ipv6 tcp
		`

	if err := set.Parse(args); err != nil {
		return err
	}

	label := set.Arg(0)

	var domain internal.Domain
	if err := domain.UnmarshalText([]byte(set.Arg(1))); err != nil {
		return err
	}

	var proto internal.Protocol
	if err := proto.UnmarshalText([]byte(set.Arg(2))); err != nil {
		return err
	}

	dp, err := e.openDispatcher(false)
	if err != nil {
		return err
	}
	defer dp.Close()

	if err := dp.UnregisterSocket(label, domain, proto); err != nil {
		return err
	}

	return nil
}
