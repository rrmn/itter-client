#!/usr/bin/env python3
"""Tests install.sh against a fake release on a local web server.

It runs install.sh the way people do (`curl ... | sh`), in a terminal and
without one, with dash and bash, for zsh, bash, fish and sh users, on Linux
and on a "Mac" (uname and sysctl faked), and checks what it says, where it
puts itter, what it adds to the shell's startup file, and that it starts
itter only when someone is at a terminal. The "itter" in the fake release is
a small stub program.

    python3 scripts/installtest.py                  # needs go, curl, dash, bash
    python3 scripts/installtest.py --release DIR    # also install a real release
                                                    # (scripts/build-release.sh)
"""
import argparse
import hashlib
import http.server
import io
import os
import platform
import pty
import select
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "6272 705b 6200 d258 80dd 12c9 7db1 911b"

STUB = r'''package main

import (
	"fmt"
	"os"
	"time"
)

var key = "KEY"

func tty(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("itter v9.9.9 (commit 0123456789ab, go1.27.1, stub)\nrelease key: %s\n", key)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "sleep" {
		time.Sleep(15 * time.Second)
		return
	}
	fmt.Printf("STUB STARTED stdin_tty=%v stdout_tty=%v\n", tty(os.Stdin), tty(os.Stdout))
}
'''

failures = []


def check(cond, what, out=""):
    if cond:
        print("  ok   " + what)
    else:
        print("  FAIL " + what)
        if out:
            print("       output was:\n" + "\n".join("       | " + l for l in out.splitlines()))
        failures.append(what)


def build_stub(work, key):
    src = os.path.join(work, "stub-" + key.replace(" ", ""))
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "main.go"), "w") as f:
        f.write(STUB.replace("KEY", key))
    with open(os.path.join(src, "go.mod"), "w") as f:
        f.write("module stub\n\ngo 1.18\n")
    out = os.path.join(src, "itter")
    env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local", GOFLAGS="-mod=mod")
    subprocess.run(["go", "build", "-o", out, "."], cwd=src, env=env, check=True)
    return out


def tarball(binary):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        t.add(binary, arcname="itter")
    return buf.getvalue()


def write_release(d, binary, corrupt=False):
    os.makedirs(d, exist_ok=True)
    data = tarball(binary)
    lines = []
    for plat in ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"):
        name = "itter_%s.tar.gz" % plat
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
        h = hashlib.sha256(data).hexdigest()
        if corrupt:
            h = "0" * 64
        lines.append("%s  %s" % (h, name))
    with open(os.path.join(d, "SHA256SUMS"), "w") as f:
        f.write("\n".join(sorted(lines, key=lambda l: l.split()[1])) + "\n")


def serve(root):
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=root, **k)
    http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def fake_mac(bindir, machine, arm64):
    os.makedirs(bindir, exist_ok=True)
    with open(os.path.join(bindir, "uname"), "w") as f:
        f.write('#!/bin/sh\ncase "$1" in -s) echo Darwin ;; -m) echo %s ;; *) echo Darwin ;; esac\n' % machine)
    with open(os.path.join(bindir, "sysctl"), "w") as f:
        if arm64:
            f.write('#!/bin/sh\n[ "$2" = hw.optional.arm64 ] && echo 1\n')
        else:
            f.write('#!/bin/sh\necho "sysctl: unknown oid \'$2\'" >&2\nexit 1\n')
    for n in ("uname", "sysctl"):
        os.chmod(os.path.join(bindir, n), 0o755)


def run(cmd, env, tty, timeout=60, until=None, send=None):
    """Runs cmd with /bin/sh. tty: in a new pseudo-terminal (the child's
    controlling terminal); otherwise detached from any terminal. Returns
    (exit status, output)."""
    if not tty:
        p = subprocess.run(["/bin/sh", "-c", cmd], env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           start_new_session=True, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="replace")
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execve("/bin/sh", ["/bin/sh", "-c", cmd], env)
        finally:
            os._exit(127)
    out = b""
    deadline = time.time() + timeout
    sent = False
    eof = False
    while time.time() < deadline and not eof:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                b = os.read(fd, 4096)
            except OSError:  # EIO: nobody has the terminal open any more
                b = b""
            if b:
                out += b
            else:
                eof = True
        if until and not sent and until.encode() in out:
            os.write(fd, send.encode())
            sent = True
    text = out.decode(errors="replace").replace("\r\n", "\n")
    if not eof:
        os.kill(pid, 9)
        text += "\n[timed out]"
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
    return (code if eof else -1), text


class World:
    """A fresh home folder and environment for one installer run."""

    def __init__(self, work, base_url, name, shell="/bin/zsh", path_extra=(), mac=None):
        self.home = os.path.join(work, "homes", name, "Home Folder")  # a space, on purpose
        self.tmp = os.path.join(work, "homes", name, "tmp")
        os.makedirs(self.home)
        os.makedirs(self.tmp)
        self.base = base_url
        self.local_bin = os.path.join(self.home, ".local", "bin")
        # Only the system's own folders: no folder the installer could pick
        # (like /opt/homebrew/bin) may be on this PATH.
        parts = list(path_extra) + ["/usr/sbin:/usr/bin:/sbin:/bin"]
        if mac:
            fake = os.path.join(work, "homes", name, "fakebin")
            fake_mac(fake, *mac)
            parts.insert(0, fake)
        self.env = {
            "HOME": self.home,
            "PATH": ":".join(parts),
            "SHELL": shell,
            "TMPDIR": self.tmp,
            "TERM": "xterm",
            "LANG": "C.UTF-8",
            "ITTER_RELEASES": base_url + "/releases",
        }

    def installer(self, sh="dash", url=None):
        assert self.env["HOME"].startswith(tempfile.gettempdir()) or "/installtest-" in self.env["HOME"]
        return 'curl -fsSL "%s" | %s' % (url or self.base + "/install.sh", sh)

    def read(self, rel):
        p = os.path.join(self.home, rel)
        return open(p).read() if os.path.exists(p) else None

    def tmp_empty(self):
        return os.listdir(self.tmp) == []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", help="a directory made by scripts/build-release.sh, to install for real")
    args = ap.parse_args()
    for tool in ("go", "curl", "dash", "bash"):
        if not shutil.which(tool):
            sys.exit("needs " + tool)

    work = tempfile.mkdtemp(prefix="installtest-")
    web = os.path.join(work, "web")
    good = build_stub(work, KEY)
    other = build_stub(work, "aaaa bbbb cccc dddd eeee ffff 0000 1111")
    for d in ("releases/latest/download", "releases/download/v9.9.9"):
        write_release(os.path.join(web, d), good)
    write_release(os.path.join(web, "releases/download/vBAD"), good, corrupt=True)
    write_release(os.path.join(web, "releases/download/vKEY"), other)
    script = open(os.path.join(ROOT, "install.sh"), "rb").read()
    with open(os.path.join(web, "install.sh"), "wb") as f:
        f.write(script)
    with open(os.path.join(web, "half.sh"), "wb") as f:
        f.write(script[: len(script) // 2])
    with open(os.path.join(web, "start.sh"), "wb") as f:
        f.write(script[: script.index(b"main() {")])
    if args.release:
        os.makedirs(os.path.join(web, "real/latest"))
        shutil.copytree(args.release, os.path.join(web, "real/latest/download"))
    srv = serve(web)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    arm = platform.machine() in ("arm64", "aarch64")
    on_mac = platform.system() == "Darwin"
    if on_mac:
        arm = arm or subprocess.run(["sysctl", "-n", "hw.optional.arm64"], capture_output=True, text=True).stdout.strip() == "1"
        host_plat = "macOS (Apple silicon)" if arm else "macOS (Intel)"
    else:
        host_plat = "Linux (ARM)" if arm else "Linux (x86-64)"
    bash_rc = ".bash_profile" if on_mac else ".bashrc"
    n = [0]

    def world(**kw):
        n[0] += 1
        return World(work, base, "w%d" % n[0], **kw)

    print("1. zsh user, ~/.local/bin not on the PATH, in a terminal, | dash")
    w = world()
    code, out = run(w.installer(), w.env, tty=True)
    check(code == 0, "exit 0", out)
    check("Installing itter for %s from %s/releases ..." % (host_plat, base) in out, "says what it installs, from where", out)
    check("Installed itter v9.9.9 in ~/.local/bin." in out, "says where it put itter", out)
    check("Added ~/.local/bin to your PATH in ~/.zshrc." in out, "says it added the folder to the PATH", out)
    check("Starting itter. Next time, open a new terminal and type: itter" in out, "says how to start it next time", out)
    check("STUB STARTED stdin_tty=true stdout_tty=true" in out, "starts itter, on the terminal", out)
    check(os.access(os.path.join(w.local_bin, "itter"), os.X_OK), "~/.local/bin/itter is there and runs")
    zshrc = w.read(".zshrc") or ""
    check(zshrc == '\n# itter (https://itter.sh)\nexport PATH="$HOME/.local/bin:$PATH"\n', ".zshrc got exactly the PATH line", zshrc)
    check(w.tmp_empty(), "its temporary folder is gone")
    check("release key" not in out and "commit" not in out, "no version dump", out)

    print("2. the same again: nothing added twice")
    code, out = run(w.installer(), w.env, tty=True)
    check(code == 0 and "Added" not in out, "no second 'Added'", out)
    check((w.read(".zshrc") or "").count("export PATH") == 1, ".zshrc has the line once")
    check("STUB STARTED" in out, "starts itter again", out)

    print("3. no terminal (output to a file or a pipe): does not start itter")
    w = world()
    code, out = run(w.installer(), w.env, tty=False)
    check(code == 0, "exit 0", out)
    check("STUB STARTED" not in out, "does not start itter", out)
    check(out.rstrip().endswith("Open a new terminal and type: itter"), "ends with how to start it", out)
    check(w.tmp_empty(), "its temporary folder is gone")

    print("4. ITTER_START=0 in a terminal")
    w = world()
    w.env["ITTER_START"] = "0"
    code, out = run(w.installer(), w.env, tty=True)
    check(code == 0 and "STUB STARTED" not in out, "does not start itter", out)

    print("5. ITTER_PATH=0: leaves the startup files alone")
    w = world()
    w.env["ITTER_PATH"] = "0"
    code, out = run(w.installer(), w.env, tty=True)
    check(code == 0, "exit 0", out)
    check("~/.local/bin is not on your PATH." in out, "says the folder is not on the PATH", out)
    check("Next time, type: %s/itter" % w.local_bin in out, "says the full path to type", out)
    check(w.read(".zshrc") is None and w.read(".profile") is None, "no startup file written")
    check("STUB STARTED" in out, "still starts itter (by its full path)", out)

    print("6. ~/.local/bin already on the PATH")
    w = world()
    os.makedirs(w.local_bin)
    w.env["PATH"] = w.local_bin + ":" + w.env["PATH"]
    code, out = run(w.installer(), w.env, tty=True)
    check(code == 0 and "Next time, just type: itter" in out, "just type itter", out)
    check(w.read(".zshrc") is None, "no startup file written")

    print("7. bash user on this computer: ~/" + bash_rc)
    w = world(shell="/bin/bash")
    code, out = run(w.installer(), w.env, tty=False)
    check(("Added ~/.local/bin to your PATH in ~/%s." % bash_rc) in out, "says ~/" + bash_rc, out)
    check('export PATH="$HOME/.local/bin:$PATH"' in (w.read(bash_rc) or ""), bash_rc + " has the line")

    print("8. bash user on a Mac: the login file bash reads")
    w = world(shell="/bin/bash", mac=("arm64", True))
    with open(os.path.join(w.home, ".profile"), "w") as f:
        f.write("# mine\n")
    code, out = run(w.installer(), w.env, tty=False)
    check("Installing itter for macOS (Apple silicon)" in out, "macOS (Apple silicon)", out)
    check("Added ~/.local/bin to your PATH in ~/.profile." in out, "uses the existing ~/.profile", out)
    check(w.read(".bash_profile") is None, "does not create ~/.bash_profile (it would hide ~/.profile)")
    w = world(shell="/bin/bash", mac=("arm64", True))
    code, out = run(w.installer(), w.env, tty=False)
    check("in ~/.bash_profile." in out and w.read(".bash_profile"), "creates ~/.bash_profile when there is none", out)

    print("9. fish user")
    w = world(shell="/usr/bin/fish")
    code, out = run(w.installer(), w.env, tty=False)
    fish = w.read(".config/fish/conf.d/itter.fish") or ""
    check('fish_add_path -g "$HOME/.local/bin"' in fish, "conf.d/itter.fish adds the folder", fish + out)

    print("10. sh user, and zsh with ZDOTDIR")
    w = world(shell="/bin/sh")
    code, out = run(w.installer(), w.env, tty=False)
    check("in ~/.profile." in out and w.read(".profile"), "~/.profile", out)
    w = world()
    zd = os.path.join(w.home, ".config", "zsh")
    os.makedirs(zd)
    w.env["ZDOTDIR"] = zd
    code, out = run(w.installer(), w.env, tty=False)
    check("in ~/.config/zsh/.zshrc." in out and w.read(".config/zsh/.zshrc"), "$ZDOTDIR/.zshrc", out)

    print("11. Macs: Intel, and Apple silicon behind Rosetta")
    w = world(mac=("x86_64", False))
    code, out = run(w.installer(), w.env, tty=False)
    check("for macOS (Intel)" in out, "Intel", out)
    w = world(mac=("x86_64", True))
    code, out = run(w.installer(), w.env, tty=False)
    check("for macOS (Apple silicon)" in out, "Rosetta terminal gets the Apple silicon program", out)

    print("12. a download that does not match SHA256SUMS")
    w = world()
    w.env["ITTER_VERSION"] = "vBAD"
    code, out = run(w.installer(), w.env, tty=True)
    check(code != 0 and "does not match the release's checksum; nothing was installed" in out, "refuses", out)
    check(not os.path.exists(os.path.join(w.local_bin, "itter")), "nothing installed")
    check(w.read(".zshrc") is None, "no startup file written")
    check(w.tmp_empty(), "its temporary folder is gone")

    print("13. a release with another release key")
    w = world()
    w.env["ITTER_VERSION"] = "vKEY"
    code, out = run(w.installer(), w.env, tty=False)
    check("Note: this release has another release key" in out, "says so", out)

    print("14. replacing an itter that is running")
    w = world()
    os.makedirs(w.local_bin)
    w.env["PATH"] = w.local_bin + ":" + w.env["PATH"]
    run(w.installer(), dict(w.env, ITTER_START="0"), tty=False)
    running = subprocess.Popen([os.path.join(w.local_bin, "itter"), "sleep"])
    time.sleep(0.3)
    code, out = run(w.installer(), dict(w.env, ITTER_START="0"), tty=False)
    check(code == 0 and "Installed itter v9.9.9" in out, "installs over it", out)
    check(running.poll() is None, "the running one keeps running")
    check(not os.path.exists(os.path.join(w.local_bin, ".itter.new")), "no leftover file")
    running.kill()

    print("15. a folder it cannot write to")
    w = world()
    ro = os.path.join(w.home, "ro")
    os.makedirs(ro)
    os.chmod(ro, 0o555)
    w.env["ITTER_INSTALL_DIR"] = ro
    code, out = run(w.installer(), w.env, tty=False)
    if os.geteuid() == 0:
        print("  skip (running as root, every folder is writable)")
    else:
        check(code != 0 and "cannot write to" in out, "refuses with a reason", out)

    print("16. | bash, | bash --posix, | sh")
    for sh in ("bash", "bash --posix", "sh"):
        w = world()
        code, out = run(w.installer(sh=sh), w.env, tty=True)
        check(code == 0 and "STUB STARTED stdin_tty=true" in out, "| " + sh, out)

    print("17. a download cut off half-way runs nothing")
    for name in ("half.sh", "start.sh"):
        w = world()
        code, out = run(w.installer(url=base + "/" + name), w.env, tty=True)
        check("Installing" not in out and not os.path.exists(w.local_bin), name + ": nothing ran", out)

    print("18. not macOS or Linux")
    w = world()
    fake = os.path.join(work, "bsd")
    os.makedirs(fake)
    with open(os.path.join(fake, "uname"), "w") as f:
        f.write("#!/bin/sh\necho FreeBSD\n")
    os.chmod(os.path.join(fake, "uname"), 0o755)
    w.env["PATH"] = fake + ":" + w.env["PATH"]
    code, out = run(w.installer(), w.env, tty=False)
    check(code != 0 and "there is no itter program for FreeBSD yet" in out, "says so", out)

    if args.release:
        print("19. a real release")
        w = world()
        w.env["ITTER_RELEASES"] = base + "/real"
        code, out = run(w.installer(), w.env, tty=False)
        version = open(os.path.join(args.release, "VERSION")).read().strip()
        check(code == 0 and ("Installed itter %s in ~/.local/bin." % version) in out, "installs " + version, out)
        check("Note:" not in out, "the release key is the one the script knows", out)
        v = subprocess.run([os.path.join(w.local_bin, "itter"), "version"], capture_output=True, text=True).stdout
        check(KEY in v and version in v, "itter version: " + v.splitlines()[0] if v else "itter version", v)
        w = world()
        w.env["ITTER_RELEASES"] = base + "/real"
        code, out = run(w.installer(), w.env, tty=True, timeout=30, until="username", send="\x03")
        check("Starting itter." in out and "Your itter username" in out, "starts itter, which asks for the username", out)

    srv.shutdown()
    shutil.rmtree(work, ignore_errors=True)
    print()
    if failures:
        print("%d FAILED:" % len(failures))
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print("all passed")


if __name__ == "__main__":
    main()
