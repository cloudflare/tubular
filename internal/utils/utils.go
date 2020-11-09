package utils

import (
	"strings"
)

// Go 1.16 exports net.ErrClosed. Until then this is the way to go.
// See https://github.com/golang/go/issues/4373 for info.
func IsErrNetClosed(err error) bool {
	if err != nil {
		return strings.HasSuffix(err.Error(), "use of closed network connection")
	}
	return false
}
