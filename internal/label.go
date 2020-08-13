package internal

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// labelID is a numeric identifier for a label.
// 0 is not a valid ID.
type labelID uint32

// systemd supports names of up to this length. Match the limit.
const maxLabelLength = unix.NAME_MAX

type label string

var _ encoding.BinaryMarshaler = label("")

func (lbl label) MarshalBinary() ([]byte, error) {
	if strings.IndexByte(string(lbl), 0) != -1 {
		return nil, fmt.Errorf("label cotains null byte")
	}
	buf := make([]byte, maxLabelLength)
	if copy(buf, lbl) != len(lbl) {
		return nil, fmt.Errorf("label exceeds maximum length of %d bytes", maxLabelLength)
	}
	return buf, nil
}

var _ encoding.BinaryUnmarshaler = (*label)(nil)

func (lbl *label) UnmarshalBinary(buf []byte) error {
	nul := bytes.IndexByte(buf, 0)
	if nul == -1 {
		*lbl = label(buf)
		return nil
	}

	*lbl = label(buf[:nul])
	return nil
}

type labels struct {
	m *ebpf.Map
}

var labelsSpec = &ebpf.MapSpec{
	Name:       "labels",
	Type:       ebpf.Hash,
	KeySize:    maxLabelLength,
	ValueSize:  uint32(unsafe.Sizeof(labelID(0))),
	MaxEntries: 512,
}

func newLabels() (*labels, error) {
	m, err := ebpf.NewMap(labelsSpec)
	if err != nil {
		return nil, fmt.Errorf("create labels: %s", err)
	}

	return &labels{m}, nil
}

func createLabels(path string) (*labels, error) {
	lbls, err := newLabels()
	if err != nil {
		return nil, err
	}

	if err := lbls.m.Pin(path); err != nil {
		return nil, fmt.Errorf("create labels: %s", err)
	}

	return lbls, nil
}

func openLabels(path string) (*labels, error) {
	m, err := ebpf.LoadPinnedMap(path)
	if err != nil {
		return nil, fmt.Errorf("can't load pinned labels: %s", err)
	}

	if err := checkMap(labelsSpec, m); err != nil {
		m.Close()
		return nil, fmt.Errorf("pinned labels: %s", err)
	}

	return &labels{m}, nil
}

func (lbls *labels) Close() error {
	return lbls.m.Close()
}

func (lbls *labels) FindID(lbl string) (labelID, error) {
	var id labelID
	err := lbls.m.Lookup(label(lbl), &id)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("find id for label %s: %s", lbl, err)
	}
	return id, nil
}

func (lbls *labels) AllocateID(lbl string) (labelID, error) {
	var (
		key       label
		id, maxID labelID
		iter      = lbls.m.Iterate()
	)
	for iter.Next(&key, &id) {
		if id > maxID {
			maxID = id
		}
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("can't find highest ID: %s", err)
	}

	id = maxID + 1
	if id < maxID {
		return 0, fmt.Errorf("allocate label: ran out of ids")
	}

	if err := lbls.m.Update(label(lbl), id, ebpf.UpdateNoExist); err != nil {
		return 0, fmt.Errorf("allocate label: %s", err)
	}

	return id, nil
}

func (lbls *labels) Delete(lbl string) error {
	if err := lbls.m.Delete(label(lbl)); err != nil {
		return fmt.Errorf("delete label: %s", err)
	}
	return nil
}
