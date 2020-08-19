package internal

import (
	"encoding/binary"
	"unsafe"
)

// nativeEndian is set to either binary.BigEndian or binary.LittleEndian,
// depending on the host's endianness.
var nativeEndian binary.ByteOrder

func init() {
	if isBigEndian() {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}
