package internal

import (
	"fmt"
	"net"
	"strings"
	"unsafe"
)

// A Binding selects which packets to redirect.
//
// You have to add a Binding to a Dispatcher for it to take effect.
type Binding struct {
	Label    string
	Protocol Protocol
	Prefix   *net.IPNet
	Port     uint16
}

// NewBinding creates a new binding.
//
// prefix may either be in CIDR notation (::1/128) or a plain IP address.
// Specifying ::1 is equivalent to passing ::1/128.
func NewBinding(label string, proto Protocol, prefix string, port uint16) (*Binding, error) {
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
		label,
		proto,
		ipn,
		port,
	}, nil
}

func newBindingFromBPF(label string, key *bindingKey) *Binding {
	ones := int(key.PrefixLen) - bindingKeyHeaderBits
	ip := make(net.IP, len(key.IP))
	copy(ip, key.IP[:])

	var prefix *net.IPNet
	if v4 := ip.To4(); v4 != nil {
		prefix = &net.IPNet{
			IP:   v4,
			Mask: net.CIDRMask(ones-(128-32), 32),
		}
	} else {
		prefix = &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(ones, 128),
		}
	}

	return &Binding{
		label,
		key.Protocol,
		prefix,
		key.Port,
	}
}

func (b *Binding) String() string {
	return fmt.Sprintf("%s#%v:[%s]:%d", b.Label, b.Protocol, b.Prefix, b.Port)
}

// bindingKey mirrors struct addr
type bindingKey struct {
	PrefixLen uint32
	Protocol  Protocol
	Port      uint16
	IP        [16]byte
}

const bindingKeyHeaderBits = int(unsafe.Sizeof(bindingKey{}.Protocol)+unsafe.Sizeof(bindingKey{}.Port)) * 8

func newBindingKey(bind *Binding) (*bindingKey, error) {
	ones, bits := bind.Prefix.Mask.Size()
	if ones == 0 && bits == 0 {
		return nil, fmt.Errorf("invalid prefix: %s", bind.Prefix)
	}

	if bits == 32 {
		ones += 128 - 32
	}

	key := bindingKey{
		PrefixLen: uint32(bindingKeyHeaderBits + ones),
		Protocol:  bind.Protocol,
		Port:      bind.Port,
	}

	if n := copy(key.IP[:], bind.Prefix.IP.To16()); n != net.IPv6len {
		return nil, fmt.Errorf("invalid IP address: expected 16 bytes, got %d", n)
	}

	return &key, nil
}

// bindingValue mirrors struct binding.
type bindingValue struct {
	ID        destinationID
	PrefixLen uint32
}
