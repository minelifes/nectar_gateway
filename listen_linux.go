//go:build linux

package main

// SO_REUSEPORT (asm-generic/socket.h); absent from the frozen stdlib
// syscall package on linux/amd64.
const soReusePort = 0xf

const reusePortSupported = true
