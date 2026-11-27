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
		fmt.Println("release key: none (a build made by hand: it cannot check updates)")
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
			return userErrf("usage: itter update [--check]")
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
		return userErrf("the newest release on GitHub is NOT signed with itter's release key, so it was not installed. Nothing was changed. If that persists, tell the itter people.")
	case err != nil:
		return userErrf("could not look for updates: %v", err)
	}
	if !release.Newer(r.Version, version) {
		fmt.Printf("itter %s is the newest release.\n", version)
		return nil
	}
	if checkOnly {
		fmt.Printf("itter %s is out (you have %s). `itter update` installs it.\n", r.Version, version)
		return nil
	}
	exe, err := release.Executable()
	if err != nil {
		return err
	}
	fmt.Printf("Downloading itter %s ...\n", r.Version)
	bin, err := f.Binary(ctx, r, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return userErrf("the download failed, nothing was changed: %v", err)
	}
	var nw *release.ErrNotWritable
	if err := release.Replace(exe, bin, r.Version); errors.As(err, &nw) {
		return userErrf("%v", err)
	} else if err != nil {
		return userErrf("%v", err)
	}
	fmt.Printf("Updated itter %s → %s (checked against the release key %s).\n", version, r.Version, release.Fingerprint())
	return nil
}
