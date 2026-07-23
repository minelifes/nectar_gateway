//go:build !linux && !darwin

package main

const soReusePort = 0

const reusePortSupported = false
