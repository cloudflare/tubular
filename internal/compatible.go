package internal

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func isLinkCompatible(link *link.NetNsLink, prog *ebpf.Program) (bool, error) {
	info, err := link.Info()
	if err != nil {
		return false, fmt.Errorf("get link info: %s", err)
	}

	linkProg, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return false, fmt.Errorf("get link program from id: %s", err)
	}
	defer linkProg.Close()

	progInfo, err := prog.Info()
	if err != nil {
		return false, fmt.Errorf("get program info: %s", err)
	}

	linkProgInfo, err := linkProg.Info()
	if err != nil {
		return false, fmt.Errorf("get dispatcher program info: %s", err)
	}

	return progInfo.Tag == linkProgInfo.Tag, nil
}
