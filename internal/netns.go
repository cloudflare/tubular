package internal

import (
	"fmt"
	"path/filepath"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

// openNetNS opens a handle to a network namespace.
//
// Returns the associated state directory.
func openNetNS(path, bpfFsPath string) (ns.NetNS, string, error) {
	var fs unix.Statfs_t
	err := unix.Statfs(bpfFsPath, &fs)
	if err != nil || fs.Type != unix.BPF_FS_MAGIC {
		return nil, "", fmt.Errorf("invalid BPF filesystem path: %s", bpfFsPath)
	}

	ns, err := ns.GetNS(path)
	if err != nil {
		return nil, "", err
	}

	var stat unix.Stat_t
	if err := unix.Fstat(int(ns.Fd()), &stat); err != nil {
		return nil, "", fmt.Errorf("can't stat netns: %s", err)
	}

	statePath := filepath.Join(bpfFsPath, fmt.Sprintf("%d_dispatcher", stat.Ino))
	return ns, statePath, nil
}
