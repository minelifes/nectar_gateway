package main

import (
	"context"
	"log"
	"net"
	"syscall"
)

// reuseportListeners opens n TCP listeners on the same address using
// SO_REUSEPORT, so the kernel load-balances incoming connections across
// n independent accept loops (one per listener). Falls back to a single
// plain listener if SO_REUSEPORT is unavailable.
func reuseportListeners(addr string, n int) ([]net.Listener, error) {
	if !reusePortSupported {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		return []net.Listener{l}, nil
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}

	var ls []net.Listener
	for i := 0; i < n; i++ {
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			if i == 0 {
				// SO_REUSEPORT unsupported? plain single listener
				l, err = net.Listen("tcp", addr)
				if err != nil {
					return nil, err
				}
				log.Printf("%s: SO_REUSEPORT unavailable, using 1 listener", addr)
				return []net.Listener{l}, nil
			}
			log.Printf("%s: stopped at %d listeners: %v", addr, i, err)
			break
		}
		ls = append(ls, l)
	}
	return ls, nil
}
