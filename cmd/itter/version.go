package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rrmn/itter-client/internal/release"
)

// Set when a release is built (-ldflags "-X main.version=v1.2.3 -X main.commit=...").
var (
	version = "dev"
	commit  = ""
)

func versionLine() string {
	parts := []string{}
	if commit != "" {
		parts = append(parts, "commit "+commit[:min(len(commit), 12)])
	}
	parts = append(parts, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
	return "itter " + version + " (" + strings.Join(parts, ", ") + ")"
}

func cmdVersion() error {
	fmt.Println(versionLine())
	if fp := release.Fingerprint(); fp != "" {
		fmt.Println("release key: " + fp)
	} else {
		fmt.Println("release key: none (a homemade build: it can't check updates)")
	}
	return nil
}

// releaseFetcher is where updates come from. ITTER_RELEASES points
// somewhere else, for tests; whatever it serves still has to be signed with
// the release key this program carries.
func releaseFetcher() *release.Fetcher {
	return &release.Fetcher{Base: os.Getenv("ITTER_RELEASES"), UA: "itter/" + version}
}

func cmdUpdate(args []string) error {
	checkOnly := false
	for _, a := range args {
		switch a {
		case "--check", "-n":
			checkOnly = true
		default:
			return userErrf("Usage: itter update [--check]")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	f := releaseFetcher()
	r, err := f.Latest(ctx)
	switch {
	case errors.Is(err, release.ErrNoKey):
		return userErrf("%v", err)
	case errors.Is(err, release.ErrSignature):
		return userErrf("Whoa: the newest release on GitHub is NOT signed with itter's release key. Not installing it, nothing changed. If this keeps happening, tell us: contact@itter.sh")
	case err != nil:
		return userErrf("Couldn't check for updates (%v). Is the internet there?", err)
	}
	if !release.Newer(r.Version, version) {
		fmt.Printf("itter %s is the newest. All good!\n", version)
		return nil
	}
	if checkOnly {
		fmt.Printf("itter %s is out (you have %s). Get it: itter update\n", r.Version, version)
		return nil
	}
	exe, err := release.Executable()
	if err != nil {
		return err
	}
	fmt.Printf("Getting itter %s...\n", r.Version)
	bin, err := f.Binary(ctx, r, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return userErrf("Download failed, nothing changed (%v).", err)
	}
	var nw *release.ErrNotWritable
	if err := release.Replace(exe, bin, r.Version); errors.As(err, &nw) {
		return userErrf("%v", err)
	} else if err != nil {
		return userErrf("%v", err)
	}
	fmt.Printf("Updated: itter %s → %s. Signed with the release key %s, all good!\n", version, r.Version, release.Fingerprint())
	return nil
}
