"""
W30 step 5 — Darwin IPC HARD-GATE lane (plan §3.7 acceptance matrix).

Boots target/debug/glmsvc FOREGROUND with a run-area svc.toml (custom
IPC path, opt-in metrics, no controller — the token handoff does not
need one), then asserts the matrix:

  [1] same-user login handoff -> caller becomes owner (status reflects)
  [2] SECOND-user login AFTER ownership -> REFUSED (ownership-sequenced
      per round-3: the rejection is only meaningful once ownership
      exists — a fresh-socket rejection would prove less)
  [3] root login AFTER ownership -> REFUSED (root is NOT the owner;
      behavior explicitly defined, plan §3.7 item 3)
  [4] connect-and-die children: the service keeps serving (per-socket
      token asserts are the svc unit tests' churn/dead-peer coverage)
  [5] churn survives: rapid connect/exit children, then the owner is
      STILL authorized (no wrong-uid denial or wedge)
  [6] stale socket file -> recreated on boot (regular-file junk at the
      path, and a SIGKILL-leftover socket, both recovered)
  [+ ] socket mode 0666 in a 0755 dir; SIGTERM graceful exit;
       /metrics carries ipc_requests_total

Second user: `sysadminctl -addUser` (passwordless sudo on the runner) +
readiness poll (round-3 fold). If creation refuses, the [2] check
prints OWNER-LANE-FALLBACK and the lane exits 1 — never silently
narrowed.

Usage: python3 tests-e2e/macos/ipc_matrix.py   (macOS, repo checkout cwd)
Exit code = FAIL count (0 = green). Run dir: ~/aztna-w30-ipc-run.
"""
import http.client
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(os.environ.get("AZTNA_REPO", str(Path.cwd())))
GLMSVC = REPO / "target" / "debug" / "glmsvc"
RUN = Path.home() / "aztna-w30-ipc-run"
HOME_DIR = RUN / "home"
SOCK = RUN / "w30-ipc.sock"
# macOS binds only CONFIGURED loopback addrs (Linux: whole 127/8) —
# stay on 127.0.0.1 with a dedicated port; the alias family the core
# lanes use gets ifconfig-aliased by the workflow step
METRICS = ("127.0.0.1", 29943)
SECOND_USER = "aztna_e2e2"
PY3 = "/usr/bin/python3"

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    print(("PASS: " if ok else "FAIL: ") + name + (f" [{detail}]" if detail else ""))
    PASS, FAIL = PASS + (1 if ok else 0), FAIL + (1 if not ok else 0)


def ipc_req(path, cmd, token=None):
    """One JSON-lines round trip over the UDS."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(str(path))
    req = {"v": 1, "cmd": cmd}
    if token is not None:
        req["token"] = token
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode()) if buf.strip() else {"ok": False, "error": "no reply"}


HELPER = r"""
import json, socket, sys
path, cmd, token = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else None)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5); s.connect(path)
req = {"v": 1, "cmd": cmd}
if token is not None: req["token"] = token
s.sendall((json.dumps(req) + "\n").encode())
buf = b""
while not buf.endswith(b"\n"):
    c = s.recv(4096)
    if not c: break
    buf += c
print(buf.decode())
"""


def sudo_ipc(user, cmd, token=None):
    args = ["sudo", "-u", user, PY3, "-c", HELPER, str(SOCK), cmd]
    if token is not None:
        args.append(token)
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired as e:
        # a bounded helper beats a traceback kill: the check FAILS
        # cleanly (lane continues, matrix visibility preserved)
        return {"ok": False, "error": f"helper timeout after 20s: {e}"}
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except Exception:
        return {"ok": False, "error": f"helper failed: {out.stderr.strip()[:200]}"}


def boot_svc():
    log = open(RUN / "glmsvc.log", "ab")
    env = dict(os.environ, AZTNA_SVC_HOME=str(HOME_DIR))
    p = subprocess.Popen([str(GLMSVC)], stdout=log, stderr=log, env=env)
    deadline = time.time() + 15
    while time.time() < deadline:
        if SOCK.exists():
            try:
                ipc_req(SOCK, "status")
                return p
            except Exception:
                pass
        if p.poll() is not None:
            raise RuntimeError(f"glmsvc exited rc={p.returncode} — see {RUN/'glmsvc.log'}")
        time.sleep(0.2)
    raise RuntimeError("glmsvc socket never came up")


def stop(p, sig):
    p.send_signal(sig)
    try:
        p.wait(timeout=10)
        return p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        return "timeout"


def scrape_metrics():
    try:
        c = http.client.HTTPConnection(METRICS[0], METRICS[1], timeout=5)
        c.request("GET", "/metrics")
        body = c.getresponse().read().decode()
        c.close()
        return body
    except Exception:
        return ""


def main():
    if not GLMSVC.exists():
        print(f"glmsvc missing at {GLMSVC} — build first", file=sys.stderr)
        return 1
    shutil.rmtree(RUN, ignore_errors=True)
    HOME_DIR.mkdir(parents=True)
    os.chmod(HOME_DIR, 0o700)
    (HOME_DIR / "svc.toml").write_text(
        f'ipc_bind = "{SOCK}"\nmetrics = "{METRICS[0]}:{METRICS[1]}"\n'
    )

    # ---- boot + socket hygiene ----------------------------------------
    p = boot_svc()
    m = os.stat(SOCK).st_mode
    check("[socket] mode is 0666", stat.S_IMODE(m) == 0o666, f"got {oct(stat.S_IMODE(m))}")
    dmode = stat.S_IMODE(os.stat(SOCK.parent).st_mode)
    check("[socket] dir is 0755", dmode == 0o755, f"got {oct(dmode)}")

    # ---- [1] same-user handoff establishes ownership -------------------
    r = ipc_req(SOCK, "login", token="w30-matrix-handoff")
    check("[1] owner login handoff ok", r.get("ok") is True, json.dumps(r)[:120])

    # ---- [2] second user refused AFTER ownership ------------------------
    created = subprocess.run(
        ["sudo", "sysadminctl", "-addUser", SECOND_USER],
        capture_output=True, text=True, timeout=60,
    )
    if created.returncode != 0:
        print(f"OWNER-LANE-FALLBACK: second-user creation refused: {created.stderr.strip()[:200]}")
        check("[2] second-user creation", False, "sysadminctl refused — owner-lane fallback, never silent")
    else:
        # readiness poll (round-3 fold): a fresh account's session may lag.
        # Probe with THE ACTUAL INTERPRETER, not /usr/bin/true: the first
        # python3 spawn as a brand-new user initializes per-user state and
        # can exceed a check's 20 s window by itself (mirror run 34811831529
        # taught this: true returned instantly, python3 -c hit 20 s).
        ready, detail = False, ""
        for _ in range(30):
            probe = subprocess.run(
                ["sudo", "-u", SECOND_USER, PY3, "-c", "print(1)"],
                capture_output=True, text=True, timeout=60)
            if probe.returncode == 0:
                ready = True
                break
            detail = probe.stderr.strip()[:120]
            time.sleep(1)
        if not ready:
            check("[2] second-user readiness", False, detail)
        else:
            r = sudo_ipc(SECOND_USER, "login", token="intruder-token")
            check("[2] second-user login REFUSED after ownership",
                  r.get("ok") is False, json.dumps(r)[:160])

    # ---- [3] root refused AFTER ownership -------------------------------
    r = sudo_ipc("root", "login", token="root-token")
    check("[3] root login REFUSED (root is not the owner)",
          r.get("ok") is False, json.dumps(r)[:160])

    # ---- [4] connect-and-die children: service keeps serving -----------
    for _ in range(5):
        subprocess.Popen([PY3, "-c",
                          f"import socket;s=socket.socket(socket.AF_UNIX);s.connect('{SOCK}');s.close()"])
        time.sleep(0.05)
    time.sleep(0.5)
    r = ipc_req(SOCK, "status")
    check("[4] service healthy after dead-peer connects", r.get("ok") is True,
          json.dumps(r)[:120])

    # ---- [5] churn: owner still authorized ------------------------------
    procs = [subprocess.Popen([PY3, "-c",
              f"import socket,time;s=socket.socket(socket.AF_UNIX);s.connect('{SOCK}');time.sleep(2)"])
             for _ in range(8)]
    time.sleep(0.4)
    for pr in procs:
        pr.kill()
    r = ipc_req(SOCK, "login", token="w30-matrix-handoff")
    check("[5] owner still authorized after churn", r.get("ok") is True,
          json.dumps(r)[:120])

    # ---- metrics carry the IPC series -----------------------------------
    body = ""
    metrics_up = False
    for _ in range(20):  # listener + first serve may lag; retry-scrape
        body = scrape_metrics()
        if "ipc_requests_total" in body:
            metrics_up = True
            break
        time.sleep(0.5)
    if not metrics_up:
        tail = (RUN / "glmsvc.log").read_text(errors="replace").splitlines()[-8:]
        print("glmsvc.log tail:" + chr(10) + "  " + chr(10) + "  ".join(tail))
    check("[metrics] ipc_requests_total present", metrics_up)

    # ---- signals: SIGTERM graceful; SIGKILL + restart recovery ----------
    rc = stop(p, signal.SIGTERM)
    check("[signal] SIGTERM exits promptly", rc is not None and rc != "timeout", f"rc={rc}")

    p = boot_svc()  # state survived; ownership is session-scoped -> fresh
    r = ipc_req(SOCK, "status")
    check("[6] restart after SIGTERM serves again", r.get("ok") is True)
    stop(p, signal.SIGKILL)
    # SIGKILL leaves the socket file behind: stale-socket recreation
    junk_was_socket = SOCK.exists()
    p = boot_svc()
    r = ipc_req(SOCK, "status")
    check("[6] stale socket (SIGKILL leftover) recreated on boot",
          junk_was_socket and r.get("ok") is True)
    # regular-file junk at the path is also removed by bind
    stop(p, signal.SIGTERM)
    SOCK.unlink(missing_ok=True)  # a socket inode: unlink before junk-write
    SOCK.write_text("junk")
    p = boot_svc()
    r = ipc_req(SOCK, "status")
    check("[6] regular-file junk at socket path removed on boot", r.get("ok") is True)

    stop(p, signal.SIGTERM)
    print(f"==== RESULT: {PASS} passed, {FAIL} failed (logs: {RUN}) ====")
    return FAIL


if __name__ == "__main__":
    sys.exit(main())
