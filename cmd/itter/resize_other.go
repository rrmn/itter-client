//go:build !unix

package main

import "os"

// notifyResize: no size-change signal here; itter keeps the starting size.
func notifyResize(ch chan<- os.Signal) {}
