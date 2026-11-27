//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyResize sends a signal on ch whenever the terminal changes size.
func notifyResize(ch chan<- os.Signal) { signal.Notify(ch, syscall.SIGWINCH) }
