package internal

import (
	"fmt"
	"net"
	"unsafe"
)

// bindingKey mirrors struct addr
type bindingKey struct {
	PrefixLen uint32
	Protocol  Protocol
	Port      uint16
	IP        [16]byte
}

func newBindingKey(prefix *net.IPNet, proto Protocol, port uint16) (*bindingKey, error) {
	const fixedHeaderBits = int(unsafe.Sizeof(bindingKey{}.Protocol)+unsafe.Sizeof(bindingKey{}.Port)) * 8

	ones, bits := prefix.Mask.Size()
	if ones == 0 && bits == 0 {
		return nil, fmt.Errorf("invalid prefix: %s", prefix)
	}

	if bits == 32 {
		ones += 128 - 32
	}

	key := &bindingKey{
		PrefixLen: uint32(fixedHeaderBits + ones),
		Protocol:  proto,
		Port:      port,
	}

	if n := copy(key.IP[:], prefix.IP.To16()); n != net.IPv6len {
		return nil, fmt.Errorf("invalid IP address: expected 16 bytes, got %d", n)
	}

	return key, nil
}
