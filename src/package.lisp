(defpackage #:arp-scan
  (:use #:cl)
  (:export #:scan
           #:scan-cidr
           #:list-interfaces
           #:main
           ;; The library half.  SCAN is the command: it formats, streams and
           ;; may exit the process, and it returns only (ip . mac).  SCAN-HOSTS
           ;; hands back the records themselves, so a caller can have the
           ;; vendor, rtt, fingerprint and timestamps that were collected
           ;; anyway.  plumb/arp is the first consumer.
           #:scan-hosts
           ;; What SCAN-HOSTS can signal about its interface, so a caller can
           ;; tell "bad -i" from a permissions failure without arp-scan::.
           #:unusable-interface
           #:unusable-interface-name #:unusable-interface-reason
           #:host #:host-p
           #:host-ip #:host-mac #:host-vendor #:host-kind #:host-rtt
           #:host-fingerprint #:host-first-seen #:host-last-seen
           #:host-reply-count #:host-request-count
           #:host-padding #:host-padding-kind #:host-alt-macs
           #:get-ifaces
           #:iface #:iface-p
           #:iface-name #:iface-flags #:iface-ip #:iface-netmask #:iface-mac
           #:iface-up-p #:iface-loopback-p
           ;; A 4- or 6-byte vector is not what a human or a table wants.
           #:format-ip #:format-mac))

(defpackage #:arp-scan.smoke
  (:use #:cl)
  (:export #:main))
