# arp-scan in Common Lisp

* uses libpcap to portably access lower networking levels
* works with SBCL (and probably others) on Linux/macOS
* includes the IEEE OUI database for converting manufacturer IDs to names

```
$ sudo arp-scan
Scanning 192.168.50.1 - 192.168.50.254 on en0 (192.168.50.118, AE:6C:AB:CC:76:73)
IP                MAC                Vendor
192.168.50.1      CC:28:AA:41:26:38  ASUSTek COMPUTER INC.
192.168.50.16     88:A2:9E:03:06:AD  Raspberry Pi (Trading) Ltd
192.168.50.136    DC:53:92:85:82:95  Apple, Inc.
192.168.50.72     26:9A:3D:BD:02:81  (randomized MAC)

4 hosts found.
```

Scanning needs raw packet privileges. `arp-scan -l`, which lists interfaces,
does not.

## Building

```sh
ocicl install     # vendor the dependencies listed in ocicl.csv
make              # builds arp-scan and arp-scan-smoke
make smoke        # run the test suite (no root required)
make setcap       # Linux: grant CAP_NET_RAW so scanning works without sudo
```

## Beyond a one-shot scan

**Watch for devices joining and leaving.** Rescans on an interval and reports
only what changed — `+` new, `-` gone, `!` an address that changed hands. A host
has to miss several consecutive rounds before it counts as gone, so one dropped
reply does not read as a departure.

```sh
sudo arp-scan --watch 30
```

**Listen without transmitting.** Emits nothing at all, learning hosts from the
ARP traffic already on the wire. Works where active scanning is filtered, and
finds hosts outside the local subnet.

```sh
sudo arp-scan --passive -w 60
```

**Notice contradictory ARP claims.** Two MACs claiming one address is what cache
poisoning looks like; one MAC answering for many addresses is worth a look,
though a proxy-ARP router does it legitimately. Gratuitous announcements and
multicast source addresses are reported too.

```sh
sudo arp-scan --anomalies-only
```

**Track an approved set of devices.** Records the network as a known-hosts file,
then flags anything absent from it. Together with `--watch` and
`--fail-on-anomaly` (which exits 2) this makes a serviceable cron job.

```sh
sudo arp-scan --write-baseline known.txt
sudo arp-scan --baseline known.txt --fail-on-anomaly
```

Because devices using MAC randomization rotate their address by design, they are
kept out of baselines and counted separately — otherwise every phone on the
network would look like an intruder on every run.

**Group hosts by ARP stack behaviour.** Sends a matrix of deliberately malformed
probes and records which ones each host answers. Hosts sharing a pattern run the
same implementation — which is often enough to tell what a device is even when
its MAC is randomized.

```sh
sudo arp-scan --fingerprint
```

No OS names are claimed. Mapping patterns to systems takes a signature table
built from known hardware, and this does not ship one.

**Machine-readable output.** `--format json|jsonl|csv`. Progress and banners go
to stderr so stdout stays parseable.

```sh
sudo arp-scan --format json | jq '.hosts[] | select(.mac_kind == "randomized")'
```

**Run a command when something happens.** Turns watch mode and baselines from
reporting into alerting. Details arrive as separate arguments — never through a
shell, so a hostile vendor string stays a string.

```sh
sudo arp-scan --watch 60 --on-new-host ./notify.sh --on-anomaly ./page.sh
```

`--on-new-host` receives `EVENT IP MAC VENDOR KIND VLAN` and needs `--watch` or
`--baseline` to say what "new" means. `--on-anomaly` receives
`KIND IP MAC OTHER-MAC DETAIL`. Randomized MACs do not trigger new-host hooks,
for the same reason they stay out of baselines.

**Pick targets flexibly.** A CIDR block, a range, a single address, or any
comma-separated mixture. Overlapping pieces are merged so nothing is asked
twice.

```sh
sudo arp-scan -r 192.168.1.0/24,10.0.0.5,10.0.0.100-150
sudo arp-scan --targets hosts.txt      # one spec per line, # for comments
```

**Wake a machine.**

```sh
sudo arp-scan --wake DC:A6:32:11:22:33
```

**VLANs.** Tagged ARP is parsed, including 802.1ad double tags, and the VLAN id
is recorded per host. Untagged networks are unaffected.

**Other flags.** `--rtt` reports per-host round-trip time, which exposes devices
sitting behind a bridge or in Wi-Fi power saving. `--retry N` makes extra passes
over addresses that stayed silent, and measurably finds hosts a single pass
misses. `--padding` shows the Ethernet padding a host replies with; most stacks
zero-fill it, but some leak buffer contents. `arp-scan --help` lists everything.

## As a library

`scan-hosts` returns the host records themselves rather than printing, so a
caller gets the vendor, round-trip time, fingerprint and timestamps that were
collected anyway.

```lisp
(dolist (h (arp-scan:scan-hosts :cidr "192.168.1.0/24"))
  (format t "~A ~A ~A~%"
          (arp-scan:format-ip (arp-scan:host-ip h))
          (arp-scan:format-mac (arp-scan:host-mac h))
          (or (arp-scan:host-vendor h) "")))
```

## Vendor data

Three IEEE registries are baked into the binary at build time: MA-L (24-bit),
MA-M (28-bit) and MA-S (36-bit). The longer two matter because IEEE has
subdivided several hundred MA-L blocks among small vendors; without them every
device in one reports as "IEEE Registration Authority". `make refresh-oui`
re-downloads all three.
