package internal

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func isLinkCompatible(link *link.NetNsLink, prog *ebpf.Program, spec *ebpf.ProgramSpec) error {
	linkInfo, err := link.Info()
	if err != nil {
		return fmt.Errorf("link info: %s", err)
	}

	// We could retrieve prog via linkInfo.Program, but that requires more
	// privileges than reading a pinned program. So we have the caller pass in
	// the pinned program and compare the IDs to make sure we have the correct one.
	progInfo, err := prog.Info()
	if err != nil {
		return fmt.Errorf("get dispatcher program info: %s", err)
	}

	if progID, _ := progInfo.ID(); progID != linkInfo.Program {
		return fmt.Errorf("program id %v doesn't match link %v", progID, linkInfo.Program)
	}

	tag, err := spec.Tag()
	if err != nil {
		return fmt.Errorf("calculate dispatcher tag: %s", err)
	}

	if tag != progInfo.Tag {
		return fmt.Errorf("loaded tag %q doesn't match %q", progInfo.Tag, tag)
	}

	return nil
}
