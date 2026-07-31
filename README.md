# arp-scan in Common Lisp

* uses libpcap to portably access lower networking levels
* works with SBCL (and probably others) on Linux/macOS 
* includes OUI database for converting manufacturer IDs to names

e.g.

```
$ arp-scan
Scanning 192.168.50.1 - 192.168.50.254 on en0 (192.168.50.149, 0A:B9:7E:A0:51:7D)
IP                MAC                Vendor
192.168.50.86     58:E6:C5:09:FE:20  Espressif Inc.
192.168.50.153    D8:3A:DD:2B:C4:42  Raspberry Pi Trading Ltd

2 hosts found.
```
