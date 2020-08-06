package internal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

type netns struct {
	ns.NetNS
	inode     uint64
	bpfFsPath string
}

func newNetns(path, bpfFsPath string) (*netns, error) {
	if _, err := os.Stat(bpfFsPath); err != nil {
		return nil, fmt.Errorf("invalid BPF filesystem path: %s", err)
	}

	ns, err := ns.GetNS(path)
	if err != nil {
		return nil, err
	}

	var stat unix.Stat_t
	if err := unix.Fstat(int(ns.Fd()), &stat); err != nil {
		return nil, fmt.Errorf("can't stat netns: %s", err)
	}

	return &netns{ns, stat.Ino, bpfFsPath}, nil
}

func (ns *netns) String() string {
	return "netns:" + ns.Path()
}

func (ns *netns) DispatcherStatePath() string {
	return filepath.Join(ns.bpfFsPath, fmt.Sprintf("%d_dispatcher", ns.inode))
}

func (ns *netns) AttachProgram(prog *ebpf.Program) (*link.RawLink, error) {
	nsLink, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(ns.Fd()),
		Program: prog,
		Attach:  ebpf.AttachSkLookup,
	})
	if err != nil {
		return nil, fmt.Errorf("can't attach program %s to netns %s: %s", prog, ns.Path(), err)
	}
	return nsLink, nil
}
