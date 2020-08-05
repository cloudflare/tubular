// +build tools

package tooldeps

// Go module support requires this workaround, to provide an explicit
// reference to vendored dependencies that are only needed for the
// build process.

import (
	_ "github.com/cilium/ebpf/cmd/bpf2go"
)
