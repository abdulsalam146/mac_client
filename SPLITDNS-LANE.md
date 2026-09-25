# split-DNS lane diagnostics

run: 36173014118  sha: bb41491628e2161ad8a13db320b1e05501499ef5  at: 2026-09-25T18:25:32Z

```
PASS: status enumerates empty after preclean [[]]
PASS: foreign resolver file survives the tick byte-identical (refuse-never-overwrite); status reports ours:false [survived=True status=[{'namespace': 'intruder.corp', 'id': 'intruder.corp', 'ours': False, 'generation': None}]]
PASS: selftest installs the scoped-resolver file (marker + nameserver) [# aztna:w43:4b72715abbf6df0f-00065c52d7790f42 managed|nameserver 127.0.0.1|]
FAIL: scutil --dns carries the scoped resolver (OS routing truth) [<not present>]
PASS: status reports ours:true with a generation [[{'namespace': 'erp.corp', 'id': 'erp.corp', 'ours': True, 'generation': '4b72715abbf6df0f-00065c52d7790f42'}]]
PASS: launchd job registered (RunAtLoad + StartInterval 30) [job=True plist=True launchctl-err=]
PASS: fresh heartbeat: tick is a no-op (owned file remains)
PASS: stale heartbeat: tick removes ONLY the owned file; foreign survives; launchd-tick evidence logged [['{"ts":1790360732427800,"kind":"splitdns_watchdog_recovered","source":"launchd-tick","rules":1}']]
PASS: uninstall-clean: owned files gone, job gone
==== RESULT: 9 passed, 1 failed ====
```
