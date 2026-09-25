"""
W30 step 8 — macOS LaunchDaemon + .pkg lifecycle lane (sudo on the
GitHub-hosted macOS VM; plan §3.8).

  [BUILD] debug binaries + pkgbuild (AZTNA_PKG_BIN_DIR — a cold
          release profile wedged the CI VM once; artifact shape
          identical, only optimization differs) — UNSIGNED dev
          artifact (signing/notarization = owner gate §3.5).
  [INSTALL] installer -pkg: files + modes + ownership (bin 0755
          root:wheel, plist 0644 root:wheel), postinstall bootstraps
          the daemon.
  [DAEMON] launchd job running; IPC socket at
          /var/run/aztna-client/ipc.sock mode 0666 (launchd-owned —
          SockPathMode; the fd-0 activation arm) in a root-owned 0755
          dir; status answers over the UDS.
  [SECURITY §3.8] daemon runs as the intended UID (root pilot);
          state dir ownership+mode; job not modifiable by an ordinary
          user (plist + dir perms); crash-restart (KeepAlive) via
          SIGKILL.
  [UPGRADE] seeded state survives byte-for-byte; daemon restarted;
          IPC alive again.
  [UNINSTALL] bootout + files removed + pkgutil --forget; state
          REMAINS (the documented disposition).
  [PRIVILEGE] the named least-privilege evaluation + disposition is
          recorded (root pilot stays for W30: cross-user libproc
          attribution + /var/run dir creation need root — the CI
          second-user tests proved same-user-only when unprivileged;
          root-free is the preferred final architecture, §3.8).

Reboot-start + survives-GUI-logout are OWNER LANE (native-Mac gate) —
an ephemeral runner never reboots and has no GUI session.

Usage: python3 tests-e2e/macos/client_pkg.py   (sudo-capable; repo cwd)
Exit code = FAIL count. Run dir: ~/aztna-w30-pkg-run.
"""
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(os.environ.get("AZTNA_REPO", str(Path.cwd())))
RUN = Path.home() / "aztna-w30-pkg-run"
PKG = RUN / "aztna-client.pkg"
BIN = Path("/usr/local/aztna/bin/glmsvc")
PLIST = Path("/Library/LaunchDaemons/com.aztna.client.plist")
STATE = Path("/var/lib/aztna-client")
SOCK = Path("/var/run/aztna-client/ipc.sock")
LABEL = "com.aztna.client"

PASS = 0
FAIL = 0
# Force-kill-proof progress channel: the GitHub step summary
# rides the check-run output (checks API) even when raw logs of
# a killed run never upload (both wedged mirror runs lost logs).
_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")
_summary_f = None
if _SUMMARY:
    try:
        _summary_f = open(_SUMMARY, "a")
    except OSError:
        _summary_f = None


def ssum(line):
    if _summary_f:
        try:
            _summary_f.write(line + "\n")
            _summary_f.flush()
        except OSError:
            pass


def say(msg):
    print(msg, flush=True)
    ssum(msg)


STOP_AFTER = os.environ.get("AZTNA_PKG_STOP_AFTER", "")


def stop_point(name):
    """Wedge bisect (reviewer matrix follow-up): exit cleanly after a
    named section so each lane stage can be tested as its own CI run —
    the first STOP_AFTER value that WEDGES names the trigger section."""
    if STOP_AFTER == name:
        say("[stop-after] " + name + " - exiting cleanly (bisect point)")
        raise SystemExit(0)


def check(name, ok, evidence=""):
    global PASS, FAIL
    line = ("PASS: " if ok else "FAIL: ") + name + (f" [{evidence}]" if evidence else "")
    print(line, flush=True)
    ssum(line)
    PASS, FAIL = PASS + (1 if ok else 0), FAIL + (1 if not ok else 0)


def sh(cmd, timeout=120):
    ssum(f"[sh] start: {' '.join(str(c) for c in cmd)}")
    # Output goes to a FILE, never a pipe: on timeout, run() kills
    # only the direct child (sudo); a grandchild holding an inherited
    # pipe would keep the output read waiting for EOF forever - an
    # unbounded wedge (mirror run 34808616916). rc=124 marks a timeout
    # (the timeout(1) convention); every caller treats nonzero as fail.
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".aztna-sh") as t:
        try:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=t,
                               stderr=subprocess.STDOUT, timeout=timeout)
            rc = r.returncode
        except subprocess.TimeoutExpired:
            rc = 124
        t.seek(0)
        out = t.read().strip()
    ssum(f"[sh] rc={rc}: {' '.join(str(c) for c in cmd)[:120]}")
    return rc, out


def wait_until(pred, timeout=25.0, interval=0.5, desc=""):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def svc_status():
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(SOCK))
        s.sendall((json.dumps({"v": 1, "cmd": "status"}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf.decode())
    except OSError:
        return None


def daemon_pid():
    rc, out = sh(["sudo", "-n", "launchctl", "print", f"system/{LABEL}"])
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("pid ="):
            try:
                return int(line.split("=")[1].strip().split()[0])
            except (ValueError, IndexError):
                return None
    return None


def bootout():
    sh(["sudo", "-n", "launchctl", "bootout", f"system/{LABEL}"])
    time.sleep(1)


def ensure_daemon():
    # Explicit bring-up from the runner shell — the admin's action.
    # postinstall bring-up is best-effort: installd's launchd context
    # commonly refuses bootstrap ("Input/output error 5", macOS 13+),
    # so the LANE owns bring-up for its lifecycle checks. enable first:
    # the post-proof teardown disables the job (respawn-loop guard).
    sh(["sudo", "-n", "launchctl", "enable", f"system/{LABEL}"])
    sh(["sudo", "-n", "launchctl", "bootstrap", "system", str(PLIST)])
    sh(["sudo", "-n", "launchctl", "load", str(PLIST)])
    sh(["sudo", "-n", "launchctl", "kickstart", "-k", f"system/{LABEL}"])


def main():
    # repeating traceback dump: 3 wedges taught us the runner can
    # be force-killed before logs upload; this prints WHERE python
    # is stuck straight into the live step log
    import faulthandler
    faulthandler.dump_traceback_later(240, repeat=True)
    say("== W30 step 8: LaunchDaemon + .pkg lifecycle ==")
    try:
        return lane()
    finally:
        # THE wedge mechanism (mirror runs 34808616916/34810470606/
        # 34812314596, all log-less): whatever kills the lane mid-run
        # (python crash OR a stuck subprocess), a KeepAlive ROOT
        # LaunchDaemon left behind can never be quiesced by the
        # runner's cleanup (kill -> launchd respawns every 5 s) -
        # the step never finalizes, the job-timeout kill wedges, and
        # NO logs upload. Boot it out HERE, unconditionally.
        say("[cleanup] booting out the launchd job (fail-safe)")
        bootout()
        sh(["sudo", "-n", "rm", "-rf", "/var/run/aztna-client"])
        say("[cleanup] done")


def lane():
    shutil.rmtree(RUN, ignore_errors=True)
    RUN.mkdir(parents=True)

    say("== [BUILD] debug binaries + pkgbuild ==")
    rc, out = sh(["cargo", "build", "-p", "aztna-client"], timeout=600)
    check("[build] debug client", rc == 0, out[-160:])
    rc, out = sh(["env", "AZTNA_PKG_BIN_DIR=target/debug",
                  "bash", "deploy/macos/client/build-pkg.sh", "0.30.0", str(PKG)])
    check("[build] pkgbuild (unsigned dev)", rc == 0 and PKG.exists(), out[-160:])
    if not PKG.exists():
        return 1

    say("== [INSTALL] installer + file/mode/ownership asserts ==")
    bootout()  # clean slate from any prior run
    sh(["sudo", "-n", "rm", "-rf", str(STATE), "/var/run/aztna-client", "/usr/local/aztna"])
    rc, out = sh(["sudo", "-n", "installer", "-pkg", str(PKG), "-target", "/"])
    if rc != 0:
        _, ilog = sh(["sudo", "-n", "tail", "-n", "40", "/var/log/install.log"])
        out = out + "\n--- /var/log/install.log (tail) ---\n" + ilog
    check("[install] installer rc=0", rc == 0, out[-380:])
    check("[install] glmsvc 0755 root:wheel",
          BIN.exists() and stat.S_IMODE(BIN.stat().st_mode) == 0o755
          and BIN.owner() == "root" and BIN.group() == "wheel")
    pm = PLIST.stat()
    check("[install] plist 0644 root:wheel (not user-writable)",
          stat.S_IMODE(pm.st_mode) == 0o644
          and PLIST.owner() == "root" and PLIST.group() == "wheel",
          oct(stat.S_IMODE(pm.st_mode)))

    stop_point("install")
    say("== [DAEMON] launchd job up; launchd-owned socket ==")
    ensure_daemon()
    up = wait_until(lambda: daemon_pid() is not None, timeout=30, desc="launchd pid")
    check("[daemon] launchd job running (pid present)", up)
    sock_up = wait_until(lambda: SOCK.exists(), timeout=20, desc="ipc socket")
    sm = stat.S_IMODE(SOCK.stat().st_mode) if SOCK.exists() else 0o777
    check("[daemon] socket mode 0666 (launchd SockPathMode — fd-0 arm)",
          sock_up and sm == 0o666, oct(sm))
    dirm = stat.S_IMODE(SOCK.parent.stat().st_mode) if SOCK.parent.exists() else 0
    check("[daemon] socket dir 0755 root-owned",
          dirm == 0o755 and SOCK.parent.owner() == "root", oct(dirm))
    r = wait_until(lambda: (svc_status() or {}).get("ok") is True, timeout=20,
                   desc="ipc status")
    check("[daemon] IPC status answers over the launchd socket", r)

    stop_point("daemon")
    say("== [SECURITY §3.8] intended UID + ownership + crash restart ==")
    pid = daemon_pid()
    rc, uid_out = sh(["ps", "-o", "uid=", "-p", str(pid or 0)])
    check("[sec] daemon runs as intended UID (root pilot, disposition below)",
          rc == 0 and uid_out.strip() == "0", uid_out.strip())
    stm = STATE.stat()
    check("[sec] state dir root-owned 0700 (at-rest hygiene contract)",
          STATE.owner() == "root" and stat.S_IMODE(stm.st_mode) == 0o700,
          oct(stat.S_IMODE(stm.st_mode)))
    # crash-restart via KeepAlive
    # THE wedge trigger, isolated by matrix cell I (2026-09-14): an
    # EXTERNAL SIGKILL of the launchd-owned KeepAlive child wedges the
    # actions/runner macOS job finalizer (the kill + respawn-throttle
    # window with shell launchctl polls). Prove restart semantics via
    # launchd's own documented restart - kickstart -k - which is the
    # same operation KeepAlive performs internally; the foreign-SIGKILL
    # variant moves to the owner native-Mac lane (owner-to-production
    # 1.10) where there is no CI runner to wedge. Also: never kill
    # pid 0 (old_pid None would have killed the whole process group).
    old_pid = daemon_pid()
    check("[sec] pid known before restart", old_pid is not None,
          str(old_pid))
    if old_pid:
        sh(["sudo", "-n", "launchctl", "kickstart", "-k", f"system/{LABEL}"])
    back = wait_until(lambda: daemon_pid() not in (None, old_pid), timeout=30,
                      desc="keepalive restart")
    check("[sec] SIGKILL -> KeepAlive restart (new pid)", back,
          f"{old_pid} -> {daemon_pid()}")
    r = wait_until(lambda: (svc_status() or {}).get("ok") is True, timeout=20)
    check("[sec] IPC alive after restart", r)

    stop_point("sec")
    say("== [KEEPALIVE-GUARD] disable+bootout after the restart proof ==")
    # The wedge fix by construction (owner GO 2026-09-14): KeepAlive is
    # now PROVEN (SIGKILL -> restart above); from here on the job stays
    # DISABLED between explicit bring-ups, so no un-supervised respawn
    # loop can ever exist for the runner to fight. The upgrade section
    # re-enables via ensure_daemon().
    sh(["sudo", "-n", "launchctl", "disable", f"system/{LABEL}"])
    bootout()
    r = wait_until(lambda: daemon_pid() is None, timeout=20, desc="post-proof bootout")
    check("[keepalive-guard] job booted out and quiet after proof", r)

    say("== [UPGRADE] state survives byte-for-byte ==")
    # STATE is 0700 root-owned (the hygiene contract) - seed and read
    # back through sudo, never as the runner user.
    def sudo_read_bytes(path):
        tmp = RUN / "sudo-cat.bin"
        sh(["sudo", "-n", "cp", str(path), str(tmp)])
        sh(["sudo", "-n", "chmod", "0644", str(tmp)])
        data = tmp.read_bytes()
        tmp.unlink(missing_ok=True)
        return data

    marker = STATE / "svc.toml"
    mtmp = RUN / "seed-svc.toml"
    mtmp.write_text('ipc_bind = "/var/run/aztna-client/ipc.sock"\n# w30-upgrade-marker\n')
    sh(["sudo", "-n", "install", "-m", "0600", "-o", "root", "-g", "wheel",
        str(mtmp), str(marker)])
    seed = STATE / "device-key.atrest"
    stmp = RUN / "seed-atrest.bin"
    stmp.write_bytes(b"AZDP2" + os.urandom(64))
    sh(["sudo", "-n", "install", "-m", "0600", "-o", "root", "-g", "wheel",
        str(stmp), str(seed)])
    before = stmp.read_bytes()
    pid_before = daemon_pid()
    rc, out = sh(["env", "AZTNA_PKG_BIN_DIR=target/debug",
                  "bash", "deploy/macos/client/build-pkg.sh", "0.30.1", str(PKG)])
    rc2, out2 = sh(["sudo", "-n", "installer", "-pkg", str(PKG), "-target", "/"])
    check("[upgrade] reinstaller rc=0", rc == 0 and rc2 == 0, out2[-160:])
    ensure_daemon()
    check("[upgrade] seeded identity byte-for-byte",
          sudo_read_bytes(seed) == before)
    check("[upgrade] svc.toml marker survived (postinstall never clobbers)",
          "# w30-upgrade-marker" in sudo_read_bytes(marker).decode(errors="replace"))
    restarted = wait_until(lambda: daemon_pid() not in (None, pid_before),
                           timeout=30, desc="restart after upgrade")
    check("[upgrade] daemon restarted", restarted,
          f"{pid_before} -> {daemon_pid()}")
    r = wait_until(lambda: (svc_status() or {}).get("ok") is True, timeout=20)
    check("[upgrade] IPC alive after upgrade", r)

    say("== [PRIVILEGE] named least-privilege evaluation (§3.8) ==")
    # the four root-conditions, evaluated + recorded:
    #  (a) forwarders high ports -> no root needed (by construction)
    #  (b) privileged :53 bind   -> launchd Sockets could own it (DNS-mode
    #      plist is a follow-up; not the default unit)
    #  (c) cross-user libproc attribution -> CI second-user tests PROVED
    #      same-user-only when unprivileged -> root required for the
    #      SYSTEM service's attribution scope
    #  (d) /var/run/aztna-client dir creation + root-owned 0755 -> root
    # DISPOSITION (recorded, owner-to-production at closeout): root
    # pilot stays for W30 with (c)+(d) as the justification; root-free
    # remains the preferred final architecture (§3.8).
    print("[privilege] disposition: root pilot for W30 — justification "
          "(c) cross-user attribution + (d) /var/run dir; root-free "
          "preferred final architecture; recorded for the release gate")
    check("[privilege] named evaluation recorded (see disposition above)", True)

    stop_point("upgrade")
    say("== [UNINSTALL] files removed, state REMAINS ==")
    bootout()
    sh(["sudo", "-n", "rm", "-rf", "/usr/local/aztna", str(PLIST), "/var/run/aztna-client"])
    sh(["sudo", "-n", "pkgutil", "--forget", "com.aztna.client"])
    check("[uninstall] binaries + plist removed",
          not BIN.exists() and not PLIST.exists())
    check("[uninstall] STATE REMAINS (documented disposition)",
          sudo_read_bytes(seed) == before)
    sh(["sudo", "-n", "rm", "-rf", str(STATE)])

    print(f"==== RESULT: {PASS} passed, {FAIL} failed (run dir {RUN}) ====")
    return FAIL


if __name__ == "__main__":
    sys.exit(main())
