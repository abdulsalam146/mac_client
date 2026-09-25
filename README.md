# aZTNA endpoint agent — client (public CI mirror)

This repository is a **read-only mirror of the client subset** of the
private aZTNA product repository. It exists so the macOS client lanes
(build/unit/format gates, the Darwin IPC acceptance matrix, the
LaunchDaemon + .pkg lifecycle lane, the x86_64 cross-build, and the
Secure Enclave availability probe) run on GitHub-hosted Apple-silicon
runners, which are free for public repositories.

What lives here: the endpoint agent (`client/`) and its two shared
crates (`aztna-common`, `aztna-keys`), plus the macOS lane scripts and
packaging. Everything else in the product — controller, gateway, wire
protocol, policy engine — stays in the private repository.

Content is synced by a script from the private repo; history here is
one commit per sync, not upstream history. Issues are disabled.

## License

Source-available. Copyright (c) 2026 Abdul Salam. All rights reserved.
No license is granted to use, copy, modify, or distribute this code.
