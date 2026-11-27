//go:build !unix

package vault

// lockDir is a no-op where flock is unavailable: on those systems, do not run
// two itter processes on the same state directory at once.
func lockDir(dir string) (unlock func(), err error) { return func() {}, nil }
