"""Drives the real itter program in a pseudo-terminal against itter's own SSH
server (the itter app's tests/dm_gate_server.py, no database) and a local
in-memory relay: log in, open the DMs with `dm` (the first time: setup), go
back with Esc, again with Ctrl-], leave itter with exit; then start again.

    go build -o bin/ ./cmd/...
    python3 scripts/viewtest.py /path/to/itter-app bin

ITTER_APP_PYTHON names the app's Python if it is not python3 (its .venv).
"""
import os, pty, re, select, signal, socket, struct, subprocess, sys, tempfile, time, fcntl, termios

APP = sys.argv[1]          # the itter app (Python)
BIN = sys.argv[2]          # dir with itter and itter-relay
PY = os.environ.get("ITTER_APP_PYTHON", "python3")

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

tmp = tempfile.mkdtemp(prefix="itter-viewtest-")
key = os.path.join(tmp, "alice")
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "alice@test", "-f", key], check=True)
pub = open(key + ".pub").read().strip()
open(os.path.join(tmp, "users.txt"), "w").write("alice " + pub + "\n")
relay_port, gate_port = free_port(), free_port()
procs = []
def start(cmd, cwd=None, ready=None):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    procs.append(p)
    if ready:
        deadline = time.time() + 30
        while time.time() < deadline:
            line = p.stdout.readline()
            if ready in line:
                return p
        raise SystemExit("did not start: %s" % cmd)
    return p
try:
    start([os.path.join(BIN, "itter-relay"), "-mem", "-users", os.path.join(tmp, "users.txt"), "-proxy-protocol",
           "-addr", "127.0.0.1:%d" % relay_port], ready="listening")
    start([PY, "-m", "tests.dm_gate_server", "--port", str(gate_port), "--relay", "127.0.0.1:%d" % relay_port,
           "--user", "alice", "--user-key", key + ".pub"], cwd=APP, ready="DM entrance on")

    env = {"HOME": tmp, "PATH": os.environ["PATH"], "TERM": "xterm-256color",
           "ITTER_DIR": os.path.join(tmp, "state"), "ITTER_HOST": "127.0.0.1:%d" % gate_port,
           "ITTER_KEY": key, "ITTER_KEYFILE": "1", "ITTER_BELL": "0"}
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(os.path.join(BIN, "itter"), ["itter"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    seen = b""
    pos = 0
    def until(pattern, timeout=30):
        global seen, pos
        rx = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
        deadline = time.time() + timeout
        start = pos
        while time.time() < deadline:
            m = rx.search(seen, start)
            if m:
                pos = m.end()
                return seen[start:m.end()]
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                seen += data
        tail = seen[start:][-600:]
        raise SystemExit("timed out waiting for %r; last output: %r" % (pattern, tail))
    def send(s):
        global pos
        pos = len(seen)  # answers come after what was sent
        os.write(fd, s.encode() if isinstance(s, str) else s)
        time.sleep(0.15)
    steps = []
    def ok(msg):
        steps.append(msg); print("ok:", msg, flush=True)

    until(r"Your itter username"); send("alice\r"); ok("asked for the username")
    mark = pos
    until(r"\(alice\)itter> "); ok("logged in, itter's prompt")
    pos = mark
    until(r"\x1b\]0;itter\x07"); ok("title set")
    send("dm\r")
    until(r"Set up DMs on this computer now\?"); ok("dm opened the DM setup (alternate screen)")
    send("\r")
    out = until(r"Press Enter to open your DMs", timeout=90); ok("DMs set up")
    if b"recovery" not in out.lower():
        raise SystemExit("no recovery code shown: %r" % out[-800:])
    ok("recovery code shown")
    send("\r")
    until(r"Direct messages \(all conversations\)"); ok("DM view shown")
    until(r"Esc: back to itter"); ok("DM view says how to go back")
    send("\x1b")
    out = until(r"\x1b\[\?1049l"); ok("left the alternate screen")
    send("help\r")
    until(r"Your DMs, end-to-end encrypted"); ok("back in itter: help shows the dm line for the program")
    send("\x1d")
    until(r"Direct messages \(all conversations\)"); ok("Ctrl-] opened the DMs")
    send("@alice hi me\r")
    time.sleep(1.0)
    send("\x1b")
    until(r"\x1b\[\?1049l"); ok("Esc back again")
    send("exit\r")
    until(r"Later!"); ok("itter said goodbye")
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        raise SystemExit("itter exited with %d; last output %r" % (code, seen[-600:]))
    if not seen.rstrip().endswith(b"\x1b[23;0t") and b"\x1b[23;0t" not in seen[-200:]:
        raise SystemExit("title not put back at the end: %r" % seen[-200:])
    ok("program ended cleanly, title put back")

    # Second start: the account is remembered and the DMs are ready.
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(os.path.join(BIN, "itter"), ["itter"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    seen, pos = b"", 0
    out = until(r"\(alice\)itter> ")
    if b"username" in out:
        raise SystemExit("asked for the username again")
    ok("second start: straight into itter")
    send("dm @alice\r")
    out = until(r"@alice")
    until(r"Esc: back to itter")
    if b"Set up DMs" in seen:
        raise SystemExit("set up again")
    ok("dm @alice opened that chat directly")
    send("\x1b")
    until(r"\x1b\[\?1049l"); ok("back")
    send("\x03")
    _, status = os.waitpid(pid, 0)
    ok("Ctrl-C ends the session as with ssh (exit %d)" % os.waitstatus_to_exitcode(status))
    print("ALL OK (%d steps)" % len(steps))
finally:
    for p in procs:
        p.kill()
