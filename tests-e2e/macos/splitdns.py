"""
W43 S5.3 — macOS split-DNS MECHANICS lane (public-mirror venue; client
ONLY, no control plane; sudo; plan §10 "client-only, stub zone map").

The /etc/resolver channel + the launchd backstop under the REAL system
services, driven through the product's own surfaces (the dev-only
`--splitdns-selftest` hook = activate + ONE real reconciler tick against
stub zone names — real files, real heartbeat, real journal, no CP):

  [PRECLEAN]  uninstall-clean + no owned files/job left from prior runs
  [STATUS-0]  --splitdns-status enumerates empty (exit 0, no lines)
  [INSTALL]   selftest installs erp.corp: file exists, marker first line
              (# aztna:w43:<gen> managed) + nameserver 127.0.0.1
  [SCOPING]   scutil --dns carries the scoped resolver: domain erp.corp,
              nameserver[0] : 127.0.0.1 (mDNSResponder picked the file
              up — the OS-routing truth, no DNS listener needed)
  [STATUS-1]  status reports ours:true + a generation
  [CONFLICT]  a pre-seeded FOREIGN file for another suffix survives a
              selftest tick untouched (refuse-never-overwrite), and the
              foreign file is reported ours:false by status
  [JOB]       the launchd job exists (plist with RunAtLoad + StartInterval
              30; launchctl print shows it)
  [TICK-FRESH] --splitdns-watchdog-check with a fresh heartbeat = no-op
              (files remain)
  [TICK-STALE] heartbeat removed -> check removes ONLY the owned file
              (foreign survives), evidence JSONL source=launchd-tick
  [CLEAN]     uninstall-clean: files gone, job gone, foreign untouched;
              then lane removes its own foreign seed

Usage: sudo python3 tests-e2e/macos/splitdns.py   (repo checkout cwd)
Exit code = FAIL count (0 = green). Home: ~/aztna-mac-splitdns-run.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(os.environ.get("AZTNA_REPO", str(Path.cwd())))
SVC = REPO / "target" / "debug" / "glmsvc"
RUN = Path.home() / "aztna-mac-splitdns-run"
HOME = RUN / "home"          # AZTNA_SVC_HOME (heartbeat/journal/evidence)
RESOLVER = Path("/etc/resolver")
PLIST = Path("/Library/LaunchDaemons/com.aztna.splitdns.watchdog.plist")
JOB = "com.aztna.splitdns.watchdog"
OWNED = "erp.corp"
FOREIGN = "intruder.corp"
FOREIGN_BODY = "# some admin tool\nnameserver 10.9.9.9\n"

FAILS = 0


def check(name, ok, detail=""):
    global FAILS
    print(("PASS" if ok else "FAIL") + f": {name}" + (f" [{detail}]" if detail else ""))
    if not ok:
        FAILS += 1


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=kw.pop("timeout", 60), **kw)


def svc(*args):
    """glmsvc with the lane svc-home (privileged ops need root — the lane
    itself runs under sudo)."""
    return run(["env", f"AZTNA_SVC_HOME={HOME}", str(SVC), *args])


def status_rules():
    r = svc("--splitdns-status")
    if r.returncode != 0:
        return None
    out = []
    for ln in r.stdout.splitlines():
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out


def main():
    RUN.mkdir(parents=True, exist_ok=True)
    HOME.mkdir(parents=True, exist_ok=True)

    svc("--splitdns-uninstall-clean")
    for f in (RESOLVER / OWNED,):
        if f.exists():
            f.unlink()
    r0 = status_rules()
    check("status enumerates empty after preclean", r0 == [], f"{r0}")

    # ---- conflict check FIRST: a second selftest MINTS A NEW GENERATION,
    # and the reconciler correctly removes owned rules of an older one
    # ("removals always converge") — run 4's lesson: doing this AFTER the
    # owned install tore down the erp.corp rule the later checks needed.
    # With the foreign file pre-seeded, the intruder selftest must refuse
    # (no install) and leave the file byte-identical.
    RESOLVER.mkdir(parents=True, exist_ok=True)
    (RESOLVER / FOREIGN).write_text(FOREIGN_BODY)
    svc("--splitdns-selftest", FOREIGN)
    surv = (RESOLVER / FOREIGN).read_text() == FOREIGN_BODY
    fr = [r for r in (status_rules() or []) if r.get("namespace") == FOREIGN]
    check(
        "foreign resolver file survives the tick byte-identical (refuse-never-overwrite); status reports ours:false",
        surv and bool(fr) and fr[0].get("ours") is False,
        f"survived={surv} status={fr}",
    )

    r_self = svc("--splitdns-selftest", OWNED)
    p = RESOLVER / OWNED
    body = p.read_text() if p.exists() else ""
    if r_self.returncode != 0 or not p.exists():
        events = ""
        cl = HOME / "client.log"
        if cl.exists():
            events = " | ".join(
                ln.strip() for ln in cl.read_text().splitlines() if "splitdns" in ln
            )[-400:]
        check("selftest install diagnostics", False,
              f"rc={r_self.returncode} out={r_self.stdout.strip()[:160]} "
              f"err={r_self.stderr.strip()[:200]} events={events}")
    lines = body.splitlines()
    marker_ok = (
        len(lines) >= 2
        and lines[0].startswith("# aztna:w43:")
        and lines[0].endswith(" managed")
        and lines[1] == "nameserver 127.0.0.1"
    )
    check("selftest installs the scoped-resolver file (marker + nameserver)", marker_ok, body.replace("\n", "|"))

    # mDNSResponder picks up /etc/resolver changes via FSEvents — delivery
    # can lag the rename by a beat (run 5: checked too early, red; run 4:
    # fast enough, green). POLL the observer like any OS-integration wait.
    scoped = False
    excerpt = "<not present>"
    for _ in range(12):
        sc = run(["scutil", "--dns"]).stdout
        dom = re.search(rf"domain\s*:\s*{re.escape(OWNED)}\b", sc)
        ns = re.search(r"nameserver\[0\]\s*:\s*127\.0\.0\.1", sc)
        excerpt = next((ln.strip() for ln in sc.splitlines() if OWNED in ln), "<not present>")
        if dom and ns:
            scoped = True
            break
        time.sleep(0.5)
    check("scutil --dns carries the scoped resolver (OS routing truth)", scoped, excerpt)

    rules = status_rules()
    mine = [r for r in (rules or []) if r.get("namespace") == OWNED]
    check(
        "status reports ours:true with a generation",
        bool(mine) and mine[0].get("ours") is True and bool(mine[0].get("generation")),
        f"{mine}",
    )

    r_lc = run(["launchctl", "print", f"system/{JOB}"])
    job_ok = PLIST.exists() and r_lc.returncode == 0
    plist_body = PLIST.read_text() if PLIST.exists() else ""
    plist_ok = "<key>RunAtLoad</key>" in plist_body and "StartInterval" in plist_body
    check("launchd job registered (RunAtLoad + StartInterval 30)", job_ok and plist_ok,
          f"job={job_ok} plist={plist_ok} launchctl-err={r_lc.stderr.strip()[:120]}")

    svc("--splitdns-watchdog-check")
    check("fresh heartbeat: tick is a no-op (owned file remains)", (RESOLVER / OWNED).exists())

    hb = HOME / "dns.heartbeat"
    if hb.exists():
        hb.unlink()  # stale-by-definition (no heartbeat at all)
    svc("--splitdns-watchdog-check")
    ev = (HOME / "splitdns-watchdog.log").read_text() if (HOME / "splitdns-watchdog.log").exists() else ""
    check(
        "stale heartbeat: tick removes ONLY the owned file; foreign survives; launchd-tick evidence logged",
        not (RESOLVER / OWNED).exists()
        and (RESOLVER / FOREIGN).read_text() == FOREIGN_BODY
        and "launchd-tick" in ev,
        ev.strip().splitlines()[-1:] if ev else "no evidence",
    )

    (RESOLVER / FOREIGN).unlink()  # lane's own seed
    svc("--splitdns-uninstall-clean")
    check(
        "uninstall-clean: owned files gone, job gone",
        not (RESOLVER / OWNED).exists() and not PLIST.exists(),
    )

    print(f"==== RESULT: {10 - FAILS} passed, {FAILS} failed ====")
    return FAILS


if __name__ == "__main__":
    sys.exit(main())
