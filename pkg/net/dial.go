package net

import (
	"net"
	"syscall"
	"time"
)

// dialControl is applied to every outbound socket the proxy, the passthrough
// and the DNS forwarder open. Nil by default; the gate sets it (SetDialMark)
// so its own traffic can be told apart from the agent's in a shared network
// namespace.
var dialControl func(network, address string, c syscall.RawConn) error

func newDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: dialControl}
}

func dialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return newDialer(timeout).Dial(network, address)
}
