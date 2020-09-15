package internal

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

// labelID is a numeric identifier for a label.
// 0 is not a valid ID.
type labelID uint32

// systemd supports names of up to this length. Match the limit.
const maxLabelLength = 255

type label string

var _ encoding.BinaryMarshaler = label("")

func (lbl label) MarshalBinary() ([]byte, error) {
	if lbl == "" {
		return nil, fmt.Errorf("label is empty")
	}
	if strings.ContainsRune(string(lbl), 0) {
		return nil, fmt.Errorf("label contains null byte")
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

type labelValue struct {
	ID    labelID
	Count uint32
}

var labelsSpec = &ebpf.MapSpec{
	Name:       "labels",
	Type:       ebpf.Hash,
	KeySize:    maxLabelLength,
	ValueSize:  uint32(binary.Size(labelValue{})),
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

func (lbls *labels) HasID(lbl string, want labelID) bool {
	var value labelValue
	err := lbls.m.Lookup(label(lbl), &value)
	if err != nil {
		return false
	}
	return value.ID == want
}

func (lbls *labels) Acquire(lbl string) (labelID, error) {
	var value labelValue
	err := lbls.m.Lookup(label(lbl), &value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return lbls.allocateID(lbl)
	}
	if err != nil {
		return 0, fmt.Errorf("find id for label %s: %s", lbl, err)
	}

	count := value.Count + 1
	if count < value.Count {
		return 0, fmt.Errorf("acquire label %q: counter overflow", lbl)
	}

	value.Count = count
	if err := lbls.m.Update(label(lbl), &value, ebpf.UpdateExist); err != nil {
		return 0, fmt.Errorf("acquire label %q: %s", lbl, err)
	}

	return value.ID, nil
}

// allocateID finds a unique identifier for a label.
//
// You must Release the label when no longer using it.
func (lbls *labels) allocateID(lbl string) (labelID, error) {
	var (
		key   label
		value labelValue
		ids   []labelID
		iter  = lbls.m.Iterate()
	)
	for iter.Next(&key, &value) {
		ids = append(ids, value.ID)
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("iterate labels: %s", err)
	}

	id := labelID(1)
	if len(ids) > 0 {
		sort.Slice(ids, func(i, j int) bool {
			return ids[i] < ids[j]
		})

		for _, allocatedID := range ids {
			if id < allocatedID {
				break
			}

			id = allocatedID + 1
			if id < allocatedID {
				return 0, fmt.Errorf("allocate label: ran out of ids")
			}
		}
	}

	value = labelValue{ID: id, Count: 1}
	if err := lbls.m.Update(label(lbl), &value, ebpf.UpdateNoExist); err != nil {
		return 0, fmt.Errorf("allocate label: %s", err)
	}

	return id, nil
}

func (lbls *labels) Release(lbl string) error {
	var value labelValue
	err := lbls.m.Lookup(label(lbl), &value)
	if err != nil {
		return fmt.Errorf("release label %q: %s", lbl, err)
	}

	if value.Count == 1 {
		err = lbls.m.Delete(label(lbl))
	} else {
		value.Count--
		err = lbls.m.Update(label(lbl), &value, ebpf.UpdateExist)
	}
	if err != nil {
		return fmt.Errorf("release label %q: %s", lbl, err)
	}

	return nil
}

func (lbls *labels) List() (map[labelID]string, error) {
	var (
		lbl    label
		value  labelValue
		labels = make(map[labelID]string)
		iter   = lbls.m.Iterate()
	)
	for iter.Next(&lbl, &value) {
		labels[value.ID] = string(lbl)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate labels: %s", err)
	}
	return labels, nil
}
