package internal

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unsafe"
)

// A Binding selects which packets to redirect.
//
// You have to add a Binding to a Dispatcher for it to take effect.
type Binding struct {
	Protocol Protocol
	Prefix   *net.IPNet
	Port     uint16
}

// NewBinding creates a new binding.
//
// prefix may either be in CIDR notation (::1/128) or a plain IP address.
// Specifying ::1 is equivalent to passing ::1/128.
func NewBinding(proto Protocol, prefix string, port uint16) (*Binding, error) {
	var ipn *net.IPNet
	if strings.Index(prefix, "/") != -1 {
		var err error
		_, ipn, err = net.ParseCIDR(prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix: %s", err)
		}
		if len(ipn.IP) == net.IPv6len && ipn.IP.To4() != nil {
			ipn.IP = ipn.IP.To4()
			ipn.Mask = ipn.Mask[net.IPv6len-net.IPv4len:]
		}
	} else {
		ip := net.ParseIP(prefix)
		if ip == nil {
			return nil, fmt.Errorf("invalid prefix: %s", prefix)
		}
		if ip.To4() != nil {
			ip = ip.To4()
		}

		bits := len(ip) * 8
		ipn = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}

	return &Binding{
		proto,
		ipn,
		port,
	}, nil
}

// bindingKey mirrors struct addr
type bindingKey struct {
	PrefixLen uint32
	Protocol  Protocol
	Port      uint16
	IP        [16]byte
}

const bindingKeyHeaderBits = int(unsafe.Sizeof(bindingKey{}.Protocol)+unsafe.Sizeof(bindingKey{}.Port)) * 8

var _ encoding.BinaryMarshaler = (*Binding)(nil)

// MarshalBinary implements encoding.BinaryMarshaler.
func (b *Binding) MarshalBinary() ([]byte, error) {
	ones, bits := b.Prefix.Mask.Size()
	if ones == 0 && bits == 0 {
		return nil, fmt.Errorf("invalid prefix: %s", b.Prefix)
	}

	if bits == 32 {
		ones += 128 - 32
	}

	key := bindingKey{
		PrefixLen: uint32(bindingKeyHeaderBits + ones),
		Protocol:  b.Protocol,
		Port:      b.Port,
	}

	if n := copy(key.IP[:], b.Prefix.IP.To16()); n != net.IPv6len {
		return nil, fmt.Errorf("invalid IP address: expected 16 bytes, got %d", n)
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, nativeEndian, &key); err != nil {
		return nil, fmt.Errorf("can't encode bindingKey: %s", err)
	}

	return buf.Bytes(), nil
}

var _ encoding.BinaryUnmarshaler = (*Binding)(nil)

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (b *Binding) UnmarshalBinary(buf []byte) error {
	var key bindingKey
	rd := bytes.NewReader(buf)
	if err := binary.Read(rd, nativeEndian, &key); err != nil {
		return fmt.Errorf("can't decode bindingKey: %s", err)
	}

	b.Protocol = key.Protocol
	b.Port = key.Port

	ones := int(key.PrefixLen) - bindingKeyHeaderBits
	ip := make(net.IP, len(key.IP))
	copy(ip, key.IP[:])

	if v4 := ip.To4(); v4 != nil {
		b.Prefix = &net.IPNet{
			IP:   v4,
			Mask: net.CIDRMask(ones-(128-32), 32),
		}
	} else {
		b.Prefix = &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(ones, 128),
		}
	}

	return nil
}

func (b *Binding) copy() *Binding {
	ip := make(net.IP, len(b.Prefix.IP))
	copy(ip, b.Prefix.IP)

	mask := make(net.IPMask, len(b.Prefix.Mask))
	copy(mask, b.Prefix.Mask)

	return &Binding{
		b.Protocol,
		&net.IPNet{
			IP:   ip,
			Mask: mask,
		},
		b.Port,
	}
}
