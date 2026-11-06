# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Common Lisp reimplementation of the `arp-scan` utility: it sends broadcast ARP
requests across a subnet via libpcap and prints IP / MAC / vendor for every host
that replies. Targets SBCL on macOS and Linux.

## Build and run

Dependencies are vendored under `ocicl/` (pinned in `ocicl.csv`) and resolved by
pointing ASDF's source registry at the working directory — builds do not touch
the network or the user's Quicklisp/ASDF config. `make` builds with
`--no-sysinit --no-userinit` deliberately; preserve that when adding targets.

`ocicl/` is gitignored, so a fresh clone has no dependencies: run `ocicl install`
(no arguments, materializing `ocicl.csv`) before the first `make`.

```sh
make                 # build both binaries (arp-scan, arp-scan-smoke)
make smoke           # build + run the smoke test binary
make clean
make refresh-oui     # re-download all three IEEE registries (MA-L, MA-M, MA-S)
make setcap          # Linux only: grant CAP_NET_RAW so scanning works without sudo
ocicl install <sys>  # add a dependency (then add it to arp-scan.asd :depends-on)
```

The binaries are ~50 MB SBCL images and are gitignored; `make clean` only removes
those two files.

Interactive/REPL load, mirroring the Makefile's registry setup:

```sh
sbcl --non-interactive --no-sysinit --no-userinit \
  --eval '(require :asdf)' \
  --eval '(asdf:initialize-source-registry `(:source-registry (:tree ,(uiop:getcwd)) :ignore-inherited-configuration))' \
  --eval '(asdf:load-system :arp-scan)' \
  --eval '(arp-scan:list-interfaces)'
```

Scanning needs raw packet privileges (`sudo ./arp-scan`); `./arp-scan -l` does not.

## CLI surface

Defined in `src/main.lisp` via clingon; the flags map straight onto `scan`'s
keyword arguments.

| Flag | Key | Default | Effect |
| --- | --- | --- | --- |
| `-i/--interface` | `:interface` | best-scoring usable iface | passed to `find-iface` |
| `-r/--range` | `:cidr` | the iface's own subnet | passed to `parse-targets`; also sets the observer's scope |
| `--targets` | — | — | file of target specs, folded into `:cidr` by `main` |
| `--on-new-host` | `:on-new-host` | — | command per new/unknown host; needs `--watch` or `--baseline` |
| `--on-anomaly` | `:on-anomaly` | — | command per anomaly raised |
| `--wake` | — | — | send a WoL magic packet and exit; handled entirely in `main` |
| `-w/--wait` | `:wait` | 2 s | listen window after the last request |
| `-d/--delay` | `:delay` | 1000 µs | throttle between sent requests |
| `-t/--retry` | `:retry` | 2 | extra passes over addresses that stayed silent |
| `-p/--passive` | `:passive` | — | listen only; opens no send handle at all |
| `-W/--watch` | `:watch` | — | seconds between rounds; runs until SIGINT |
| `-f/--format` | `:format` | `text` | `text`, `json`, `jsonl`, `csv` |
| `--padding` | `:padding` | — | show the Ethernet padding each host replies with |
| `--anomalies-only` | `:anomalies-only` | — | report only conflicting ARP claims |
| `--rtt` | `:rtt` | — | per-host round-trip time |
| `--fingerprint` | `:fingerprint` | — | malformed-probe matrix, grouped by response pattern |
| `--baseline` | `:baseline` | — | known-hosts file to compare against |
| `--write-baseline` | `:write-baseline` | — | save the hosts found as the approved set |
| `--fail-on-anomaly` | `:fail-on-anomaly` | — | exit 2 on unknown hosts or anomalies |
| `-l/--list` | `:list` | — | `list-interfaces` and exit, no root needed |

`--version` comes from `version-string:define-version-parameter`, which installs
an `asdf:perform :before` on `program-op` — the git hash is stamped at *build*
time, so a REPL-loaded `+version+` shows only the bare `.asd` `:version`.

## Testing

`src/smoke.lisp` is the entire test suite: a standalone binary
(`arp-scan/smoke` system) that exercises everything *except* sending and
receiving packets — CFFI library loading, `getifaddrs` enumeration, CIDR math,
OUI lookup, ARP frame layout and parsing, padding classification, anomaly
detection, output escaping, and the capture queue. It needs no root and exits
non-zero on any failure.

`make-arp-frame` in that file synthesizes frames, which is how the parser and
observer get driven without a live capture. Keep new logic reachable from plain
byte vectors so it stays testable this way.

Section `[16]` drives the scan loop itself. `run-passes` takes a send function
rather than a pcap handle, so `make-fake-net` can stand in for the network:
it counts sends and queues replies on behalf of whichever addresses the test
says should answer, on whichever attempt. That covers the pass/retry cycle —
retries narrowing to silent addresses, a host answering only on the second try,
`--retry 0` meaning one pass — with no NIC and no root. Anything added to the
scan loop belongs behind that seam; if it needs a handle to test, it is in the
wrong function.

There is no per-test runner. To run one check in isolation, load the system in a
REPL and call the internal function directly (e.g. `(arp-scan::cidr-range
"10.0.0.0/30")`). To add a check, add a `require!` form inside `main` in
`src/smoke.lisp`; `require!` swallows the error, prints `FAIL`, and flips
`all-ok`, so the run always reaches the end and reports every failure.

Section `[2]` is environment-dependent, not logic-dependent: it demands the host
have an up, non-loopback interface with IPv4 + netmask + MAC, and that
`default-iface` not land on `169.254.x.x`. It will fail on a container or a
network-less CI box without anything being wrong with the code — check the host
before debugging `src/interface.lisp`. Every other section is hermetic.

## Architecture

`arp-scan.asd` uses `:serial t`, so the component order in the `.asd` *is* the
load order — a new file must be inserted at the right position, not appended.
Everything lives in one `arp-scan` package (`src/package.lisp`); only `scan`,
`scan-cidr`, `list-interfaces`, and `main` are exported, so tests and REPL work
reach internals via `arp-scan::`. `src/smoke.lisp` is the sole exception — it
lives in `arp-scan.smoke`, also declared in `src/package.lisp`, and belongs to
the separate `arp-scan/smoke` system.

Layers, bottom-up:

- **`src/libpcap.lisp`** — CFFI bindings to libpcap plus thin Lisp wrappers
  (`pcap-open-live`, `pcap-setfilter`, `pcap-sendpacket`, `pcap-next-packet`)
  that signal the `pcap-error` condition instead of returning error codes.
  `main` catches `pcap-error` specifically to print the "needs root" hint.
- **`src/capture.lisp`** — the background capture thread and its bounded frame
  queue. `capture-drain` swaps in a fresh queue rather than copying, so the lock
  is held for O(1). Knows nothing about ARP, which is what lets the smoke test
  drive the queue without a handle.
- **`src/interface.lisp`** — `getifaddrs(3)` walk producing `iface` structs
  (name, flags, IPv4, netmask, MAC). `iface-unusable-reason` is the single
  definition of "usable": `usable-iface-p`, `find-iface`, `default-iface` and
  `list-interfaces` all go through it, and its `:needs` argument is how
  `--wake` and an explicit `-r` ask for less. The link-type test needs an open
  handle, so it is separate (`check-datalink`); `probe-datalink` lets `-l` and
  `default-iface` apply it too when running as root. `default-iface` scores
  candidates, penalizing link-local addresses and favoring `en0`.
- **`src/arp.lisp`** — pure byte-level code with no I/O: Ethernet+ARP frame
  construction per RFC 826, and IP/CIDR arithmetic on `u32` integers. `parse-arp`
  handles requests and replies alike and hands back the trailing padding;
  `parse-arp-reply` is a thin wrapper that keeps the old reply-only contract.
  Ranges exclude network and broadcast addresses for prefixes ≤ 30.
- **`src/oui.lisp`** — IEEE vendor tables at three prefix lengths (MA-L /24,
  MA-M /28, MA-S /36), with `oui-lookup` trying longest-prefix first. One parser
  reads both extended files: the width of each record's address range *is* the
  prefix length, so nothing has to be told which file it is reading.
- **`src/observer.lisp`** — folds frames into `host` records and raises
  `anomaly`s (`:ip-conflict`, `:mac-multi-ip`, `:gratuitous`). No I/O and no
  libpcap, so it is directly testable. Streaming output happens through the
  `on-host` / `on-anomaly` callbacks the scanner installs.
- **`src/output.lisp`** — text / JSON / JSONL / CSV emitters with hand-rolled
  escaping, and `progress-stream`, which decides whether banners go to stdout or
  stderr.
- **`src/baseline.lisp`** — known-hosts file, keyed on MAC because DHCP makes IP
  meaningless as identity. Line-oriented, not JSON: we have a JSON writer but no
  reader, and a flat MAC list does not justify one.
- **`src/hooks.lisp`** — runs a user command on new hosts and anomalies, passing
  details as argv. See the shell note below before changing anything here.
- **`src/fingerprint.lisp`** — the malformed-probe matrix, `build-arp-probe`
  (which lets any field be invalid, unlike `build-arp-request`), and grouping by
  response pattern.
- **`src/scanner.lisp`** — `scan` drives the whole thing: start the capture
  thread, send a pass across the range, `pump` the queue for `wait-seconds`, then
  retry only the addresses that stayed silent. Also holds watch mode and its
  round-to-round diff.
- **`src/main.lisp`** — clingon CLI definition, option-combination checks, and
  error handling. `dispatch` does the work; `handler` wraps it in the
  `handler-case` that turns conditions into exit codes.

### Twelve things that bite

**Error handling must live inside `handler`, not around `clingon:run`.**
`clingon:run` wraps the command handler in its own `handler-case` ending in a
catch-all `error` clause (`clingon/src/command.lisp:873`). Anything signalled
from the handler is caught there, printed bare, and turned into an exit — it
never reaches a `handler-case` wrapped around `clingon:run`. The needs-root hint
for `pcap-error` sat unreachable for exactly this reason until it was moved
into `handler`. `main`'s remaining `handler-case` is only a backstop for
failures outside the run, such as building the command. Any new condition that
needs a specific exit code goes in `handler`.

**The OUI table is baked into the image.** `*oui-table*` is a `defparameter`
evaluated at *load* time via `asdf:system-relative-pathname`, so the parsed hash
table is captured in the dumped binary and `data/oui.txt` is never read at
runtime. Changing the data file requires a rebuild, and the binary must stay
self-contained — don't make it depend on the file's runtime presence.

**Foreign struct layouts differ per platform** and are hand-offset rather than
groveled. `timeval.tv_usec` is `int32` on Darwin but `long` on glibc Linux;
`sockaddr` has an `sa_len` byte on Darwin/BSD but not Linux (see
`sockaddr-family`); link-layer addresses arrive as `AF_LINK`/`sockaddr_dl` (18)
on Darwin and `AF_PACKET`/`sockaddr_ll` (17) on Linux. Any new foreign struct or
offset needs both variants, and changes here should be verified on both macOS
and Linux with `make smoke`.

**Capture and send use two separate pcap handles.** A `pcap_t` is not safe for
concurrent use from two threads, so the capture thread owns one exclusively and
`scan-once` opens a second purely to transmit. Do not "simplify" this into a
shared handle — it removes the need for any locking around libpcap, and the only
shared state left is the frame queue. The capture handle is put in non-blocking
mode, which is also what makes `stop-capture`'s untimed `bt:join-thread` safe:
every loop iteration returns within about a millisecond and rechecks the flag.

**We learn from ARP requests, not just replies, so results need scoping.** Since
`parse-arp` accepts opcode 1, an unscoped observer picks up every host
chattering on the segment — including ones outside the range the user asked for.
`scan-once` therefore sets `observer-scope` to the target range, and
`in-scope-p` drops the rest. Without that, `-r 10.0.0.0/30` quietly returns
hosts from the local subnet. Passive mode deliberately leaves the scope unset.
Relatedly, the capture BPF filter excludes our own source MAC, or our outgoing
broadcasts would come back and register us as a discovered host.

**A scan is a list of segments, not one range, and VLAN tags shift everything.**
`parse-targets` returns merged `(lo . hi)` u32 pairs, so `-r` accepts CIDR
blocks, ranges (`10.0.0.1-50`), single addresses and comma-separated
combinations; overlapping specs are coalesced so nothing is asked twice.
`observer-scope` is that same segment list. Separately, an 802.1Q tag sits
between the source MAC and the ethertype and pushes the ARP payload out four
bytes (802.1ad stacks two), so `arp-offset` finds the payload rather than
assuming offset 14 — and the capture filter must be `arp or (vlan and arp)`,
because libpcap's `arp` primitive tests a fixed offset and never matches a
tagged frame. Before that, the scanner saw nothing at all on a trunk port.

**Hooks pass data as argv, never through a shell.** Vendor strings come off the
network and are attacker-chosen; `uiop:run-program` with a list and no
`:force-shell` executes the file directly, so they can only ever be arguments.
A smoke check pins this by passing `x; touch <file>` as a vendor and asserting
the file is not created. Hooks also skip randomized MACs for new-host events,
matching why they are excluded from the baseline count — otherwise it is one
alert per phone per round.

**Ranges are walked, never listed, and user input is validated first.** A
mistyped `/99` used to make `(ash #xffffffff -67)` zero, so the mask vanished,
the range became all of IPv4, and the scanner materialized 4.3 billion conses
before sending a packet — heap exhaustion from one wrong digit. `cidr-range`
now bounds the prefix and `parse-ip` checks its octets, both signalling
`invalid-target` so `main` can report a usage error rather than letting a raw
`parse-integer` or `aref` type error out. `send-pass` walks `first..last`
directly and returns a count, so nothing proportional to the range is ever
allocated; retries re-walk with `:skip-answered` instead of building a pending
list. Keep it that way — a `/8` is 16 million addresses.

**`scan` must not exit the process.** It returns `(values alist status)`, where
status is a plist of `:unknown` and `:anomalies` counts, and `main` decides what
that means for `--fail-on-anomaly`. This is library code — `plumb` consumes it
via `scan-hosts` — and a library call that can terminate its caller is a trap.

**Randomized MACs break anything that treats a MAC as an identity.** Phones and
laptops rotate their address per SSID and periodically after that, so a
MAC-keyed baseline sees a brand-new device every run. Both halves of
`src/baseline.lisp` account for this: `write-baseline` records them as comments
only (an entry that can never match again becomes a permanent "expected but not
seen"), and `report-baseline` counts them separately so `--fail-on-anomaly` does
not fire on ordinary churn. Anything new keyed on MAC needs the same treatment —
check `host-kind` first. Note this cuts the other way for fingerprinting, which
groups a rotating device with its own kind by stack behaviour regardless of what
address it is currently wearing.

**Wi-Fi power saving makes single scans incomplete, and probe timing fragile.**
Measured round trips on real devices exceed 300 ms, because the AP holds frames
until the next DTIM beacon. Two consequences. A baseline built from one scan will
miss hosts — build it from a long or repeated observation before trusting
`--fail-on-anomaly`. And a fixed fingerprint timeout silently turns "asleep" into
"did not answer this probe", so `probe-wait-for` scales the wait from the
slowest RTT already measured, and `fingerprint-reliable-p` discards any pattern
whose control-probe bit is 0 — a host that ignores a well-formed request while
answering malformed ones has described our timeout, not its stack. Measured over
three consecutive runs, patterns are otherwise reproducible.

**Adding a slot to a struct needs the fasl cache cleared.** `:serial t` does not
save you here: a downstream file compiled against the old layout gets reloaded
from `~/.cache/common-lisp/...` and SBCL dies with "attempt to redefine the
STRUCTURE-OBJECT class incompatibly". `make clean` does not touch that cache —
remove `~/.cache/common-lisp/sbcl-*/<abs-path-to-repo>` and rebuild.
