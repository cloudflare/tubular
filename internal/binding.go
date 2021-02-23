package internal

import (
	"bytes"
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

// Bindings is a list of bindings.
//
// They may be sorted using sort.Sort in the order of precedence used by the
// data plane, with the most specific binding at the start of the list.
type Bindings []*Binding

func (sb Bindings) Len() int      { return len(sb) }
func (sb Bindings) Swap(i, j int) { sb[i], sb[j] = sb[j], sb[i] }
func (sb Bindings) Less(i, j int) bool {
	a, b := sb[i], sb[j]

	if a.Protocol != b.Protocol {
		return a.Protocol < b.Protocol
	}

	// NB: This can't discern between real IPv4 and v6 mapped v4.
	if (a.Prefix.IP.To4() == nil) != (b.Prefix.IP.To4() == nil) {
		// IPv4 before IPv6
		return a.Prefix.IP.To4() != nil
	}

	// Both IP addresses are the same version, compare the v6 mapped address.
	aOnes, _ := v6Mask(a.Prefix.Mask.Size())
	bOnes, _ := v6Mask(b.Prefix.Mask.Size())

	shorterMask := aOnes
	if bOnes < aOnes {
		shorterMask = bOnes
	}

	// To16 returns the original if the IP is already IPv6
	maskedA := copyIP(a.Prefix.IP.To16())
	maskedB := copyIP(b.Prefix.IP.To16())
	for i, mask := range net.CIDRMask(shorterMask, 128) {
		maskedA[i] &= mask
		maskedB[i] &= mask
	}

	if aOnes != bOnes && bytes.Equal(maskedA, maskedB) {
		// Both prefixes overlap, like fd::/64 and fd::1. The longer prefix
		// is more specific.
		return aOnes > bOnes
	}

	if c := bytes.Compare(a.Prefix.IP.To16(), b.Prefix.IP.To16()); c != 0 {
		// Prefixes don't share a prefix, use lexicographical order.
		return c < 0
	}

	// Prefixes are identical, discern by port.
	if a.Port != b.Port {
		if a.Port == 0 || b.Port == 0 {
			// Wildcard is less specific than a real port.
			return a.Port > b.Port
		}

		// No wildcard, low ports go first.
		return a.Port < b.Port
	}

	return a.Label < b.Label
}

func v6Mask(ones, bits int) (int, int) {
	if bits == 32 {
		return ones + (128 - 32), 128
	}
	// This doesn't handle masks that are neither IPv4 not IPv6 sized, because
	// net.IPNet is a silly format.
	return ones, bits
}

func copyIP(ip net.IP) net.IP {
	cpy := make(net.IP, len(ip))
	copy(cpy, ip)
	return cpy
}

func diffBindings(have, want map[bindingKey]string) (added, removed []*Binding) {
	for key, label := range want {
		if have[key] != label {
			added = append(added, newBindingFromBPF(label, &key))
		}
	}

	for key, label := range have {
		if want[key] == "" {
			removed = append(removed, newBindingFromBPF(label, &key))
		}
	}

	return
}
