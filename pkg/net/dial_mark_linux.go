//go:build linux

package net

import (
	"context"
	"net"
	"syscall"
)

// SetDialMark makes every socket this package dials -- and every DNS lookup
// through net.DefaultResolver, which the resolved-IP guard uses -- carry
// SO_MARK mark. Call it once, before any traffic. Setting SO_MARK needs
// CAP_NET_ADMIN (or CAP_NET_RAW since Linux 5.17); a process without either
// cannot forge the mark.
func SetDialMark(mark int) {
	dialControl = func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return sockErr
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return newDialer(0).DialContext(ctx, network, address)
		},
	}
}
