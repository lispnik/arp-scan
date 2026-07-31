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

```sh
make                 # build both binaries (arp-scan, arp-scan-smoke)
make smoke           # build + run the smoke test binary
make clean
make refresh-oui     # re-download data/oui.txt from standards-oui.ieee.org
make setcap          # Linux only: grant CAP_NET_RAW so scanning works without sudo
ocicl install <sys>  # add a dependency (then add it to arp-scan.asd :depends-on)
```

Interactive/REPL load, mirroring the Makefile's registry setup:

```sh
sbcl --non-interactive --no-sysinit --no-userinit \
  --eval '(require :asdf)' \
  --eval '(asdf:initialize-source-registry `(:source-registry (:tree ,(uiop:getcwd)) :ignore-inherited-configuration))' \
  --eval '(asdf:load-system :arp-scan)' \
  --eval '(arp-scan:list-interfaces)'
```

Scanning needs raw packet privileges (`sudo ./arp-scan`); `./arp-scan -l` does not.

## Testing

`src/smoke.lisp` is the entire test suite: a standalone binary
(`arp-scan/smoke` system) that exercises everything *except* sending and
receiving packets — CFFI library loading, `getifaddrs` enumeration, CIDR math,
OUI lookup, and ARP frame byte layout. It needs no root and exits non-zero on
any failure.

There is no per-test runner. To run one check in isolation, load the system in a
REPL and call the internal function directly (e.g. `(arp-scan::cidr-range
"10.0.0.0/30")`). To add a check, add a `require!` form inside `main` in
`src/smoke.lisp`.

## Architecture

`arp-scan.asd` uses `:serial t`, so the component order in the `.asd` *is* the
load order — a new file must be inserted at the right position, not appended.
Everything lives in one `arp-scan` package (`src/package.lisp`); only `scan`,
`scan-cidr`, `list-interfaces`, and `main` are exported, so tests and REPL work
reach internals via `arp-scan::`.

Layers, bottom-up:

- **`src/libpcap.lisp`** — CFFI bindings to libpcap plus thin Lisp wrappers
  (`pcap-open-live`, `pcap-setfilter`, `pcap-sendpacket`, `pcap-next-packet`)
  that signal the `pcap-error` condition instead of returning error codes.
  `main` catches `pcap-error` specifically to print the "needs root" hint.
- **`src/interface.lisp`** — `getifaddrs(3)` walk producing `iface` structs
  (name, flags, IPv4, netmask, MAC). `default-iface` scores candidates,
  penalizing link-local addresses and favoring `en0`.
- **`src/arp.lisp`** — pure byte-level code with no I/O: Ethernet+ARP frame
  construction/parsing per RFC 826, and IP/CIDR arithmetic on `u32` integers.
  Ranges exclude network and broadcast addresses for prefixes ≤ 30.
- **`src/oui.lisp`** — IEEE OUI vendor table keyed by the 24-bit prefix.
- **`src/scanner.lisp`** — `scan` drives the whole thing: blast requests with a
  per-host delay, opportunistically draining replies between sends, then listen
  for `wait-seconds` more. Results are deduped in a hash table keyed by IP-as-u32
  and printed as they arrive.
- **`src/main.lisp`** — clingon CLI definition and top-level error handling.

### Two things that bite

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
