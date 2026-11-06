(in-package #:arp-scan)

;;; Network interface discovery via getifaddrs(3) on Darwin / BSD / Linux.
;;; Returns IP, MAC, netmask, and flags for each interface.

(defconstant +af-inet+ 2)
;; AF_LINK = 18 on Darwin/BSD; AF_PACKET = 17 on Linux. Try both.
(defconstant +af-link-darwin+ 18)
(defconstant +af-packet-linux+ 17)

(defconstant +iff-up+ #x0001)
(defconstant +iff-loopback+ #x0008)
(defconstant +iff-running+ #x0040)

(cffi:defcstruct ifaddrs
  (ifa-next :pointer)
  (ifa-name :pointer)
  (ifa-flags :uint)
  (ifa-addr :pointer)
  (ifa-netmask :pointer)
  (ifa-dstaddr :pointer)
  (ifa-data :pointer))

;; Generic sockaddr header (Darwin/BSD have sa_len + sa_family; Linux has
;; sa_family only as u16).  We only need sa_family, which on Darwin/BSD is the
;; second byte. On Linux it's the first two bytes.

(cffi:defcfun ("getifaddrs" %getifaddrs) :int
  (ifap :pointer))

(cffi:defcfun ("freeifaddrs" %freeifaddrs) :void
  (ifap :pointer))

(defun sockaddr-family (sa)
  "Read family from a sockaddr pointer."
  #+darwin (cffi:mem-aref sa :uint8 1)
  #-darwin (cffi:mem-aref sa :uint16 0))

(defun read-sockaddr-in (sa)
  "Return the 4-byte IPv4 address as a vector from a sockaddr_in pointer."
  (let ((bytes (make-array 4 :element-type '(unsigned-byte 8))))
    ;; sin_addr begins at offset 4 on both Darwin and Linux.
    (loop for i from 0 below 4
          do (setf (aref bytes i) (cffi:mem-aref sa :uint8 (+ 4 i))))
    bytes))

(defun read-sockaddr-dl-mac (sa)
  "Return the 6-byte MAC from a Darwin/BSD sockaddr_dl pointer, or NIL if alen != 6."
  (let ((nlen (cffi:mem-aref sa :uint8 5))
        (alen (cffi:mem-aref sa :uint8 6)))
    (when (= alen 6)
      (let ((mac (make-array 6 :element-type '(unsigned-byte 8))))
        (loop for i from 0 below 6
              do (setf (aref mac i) (cffi:mem-aref sa :uint8 (+ 8 nlen i))))
        mac))))

(defun read-sockaddr-ll-mac (sa)
  "Return the 6-byte MAC from a Linux sockaddr_ll pointer."
  ;; struct sockaddr_ll: family(2) protocol(2) ifindex(4) hatype(2) pkttype(1) halen(1) addr[8]
  (let ((halen (cffi:mem-aref sa :uint8 11)))
    (when (= halen 6)
      (let ((mac (make-array 6 :element-type '(unsigned-byte 8))))
        (loop for i from 0 below 6
              do (setf (aref mac i) (cffi:mem-aref sa :uint8 (+ 12 i))))
        mac))))

(defstruct iface
  name
  flags
  ip                                    ; 4-byte vector or NIL
  netmask                               ; 4-byte vector or NIL
  mac)                                  ; 6-byte vector or NIL

(defun iface-up-p (iface)
  (let ((f (iface-flags iface)))
    (and (plusp (logand f +iff-up+))
         (plusp (logand f +iff-running+)))))

(defun iface-loopback-p (iface)
  (plusp (logand (iface-flags iface) +iff-loopback+)))

(defun get-ifaces ()
  "Return a list of IFACE structs by walking getifaddrs(3)."
  (cffi:with-foreign-object (head-ptr :pointer)
    (when (/= 0 (%getifaddrs head-ptr))
      (error "getifaddrs failed"))
    (let ((head (cffi:mem-ref head-ptr :pointer))
          (table (make-hash-table :test 'equal)))
      (unwind-protect
           (loop with cur = head
                 until (cffi:null-pointer-p cur)
                 do (let* ((name (cffi:foreign-string-to-lisp
                                  (cffi:foreign-slot-value cur '(:struct ifaddrs) 'ifa-name)))
                           (flags (cffi:foreign-slot-value cur '(:struct ifaddrs) 'ifa-flags))
                           (addr (cffi:foreign-slot-value cur '(:struct ifaddrs) 'ifa-addr))
                           (mask (cffi:foreign-slot-value cur '(:struct ifaddrs) 'ifa-netmask))
                           (iface (or (gethash name table)
                                      (setf (gethash name table)
                                            (make-iface :name name :flags flags)))))
                      (setf (iface-flags iface) flags)
                      (unless (cffi:null-pointer-p addr)
                        (let ((fam (sockaddr-family addr)))
                          (cond
                            ((= fam +af-inet+)
                             (setf (iface-ip iface) (read-sockaddr-in addr))
                             (unless (cffi:null-pointer-p mask)
                               (setf (iface-netmask iface) (read-sockaddr-in mask))))
                            ((= fam +af-link-darwin+)
                             (let ((mac (read-sockaddr-dl-mac addr)))
                               (when mac (setf (iface-mac iface) mac))))
                            ((= fam +af-packet-linux+)
                             (let ((mac (read-sockaddr-ll-mac addr)))
                               (when mac (setf (iface-mac iface) mac))))))))
                    (setf cur (cffi:foreign-slot-value cur '(:struct ifaddrs) 'ifa-next)))
        (%freeifaddrs head))
      (alexandria:hash-table-values table))))

(defun iface-unusable-reason (iface &key (needs '(:ip :netmask)))
  "Why IFACE cannot carry a scan, as a string, or NIL if it can.

This is the one definition of \"usable\": DEFAULT-IFACE filters on it,
FIND-IFACE signals it, and LIST-INTERFACES prints it beside each interface it
rejects, so -i, the default and -l can never disagree about what counts. The
checks are ordered most-specific first so the message names the actual obstacle
rather than the first missing field.

A hardware address and a link that is up are always required: both ARP and
Wake-on-LAN put an Ethernet frame on the wire. NEEDS lists what else the caller
depends on, from :IP (the source address of our requests) and :NETMASK (only
consulted when the target range is derived from the interface). Wake-on-LAN
needs neither, and a scan with an explicit -r never reads the netmask, so
demanding them refused invocations that used to work.

What libpcap thinks of the link is a separate question, answered by
DATALINK-UNUSABLE-REASON, because it needs an open handle to ask."
  (cond
    ((iface-loopback-p iface)
     "it is the loopback interface, which has no peers to ask")
    ((null (iface-mac iface))
     ;; Kept to one clause: -l prints this once per tunnel, and a VPN-heavy
     ;; machine has dozens.
     "it has no hardware address (a tunnel or point-to-point link, not Ethernet)")
    ;; Link state before addresses: an unplugged port usually has no IPv4
    ;; either, and "no carrier" is the obstacle the user can do something
    ;; about. IFF_UP without IFF_RUNNING is exactly that case, and reporting
    ;; it as "down" would have ifconfig disagree with us.
    ((zerop (logand (iface-flags iface) +iff-up+))
     "it is down")
    ((zerop (logand (iface-flags iface) +iff-running+))
     "it has no carrier (up, but no link)")
    ((and (member :ip needs) (null (iface-ip iface)))
     "it has no IPv4 address")
    ((and (member :netmask needs) (null (iface-netmask iface)))
     "it has no IPv4 netmask")
    (t nil)))

(defun usable-iface-p (i)
  (null (iface-unusable-reason i)))

(defconstant +dlt-en10mb+ 1
  "libpcap's link type for Ethernet, the only one carrying ARP.")

(defun datalink-unusable-reason (dlt)
  "Why a handle reporting link type DLT cannot carry a scan, or NIL if it can.

IFACE-UNUSABLE-REASON rejects anything without a hardware address, which
catches tunnels already. This asks libpcap's own opinion, so a device that has
a MAC but hands us something other than Ethernet frames is caught too, rather
than being parsed as though it were."
  (unless (= dlt +dlt-en10mb+)
    (format nil "libpcap reports link type ~D, not Ethernet (~D), ~
                 so frames on it carry no ARP"
            dlt +dlt-en10mb+)))

(defun probe-datalink (name)
  "The link type libpcap reports for NAME, or NIL when it cannot be opened.

Opening needs raw packet privileges, so without root this is NIL for every
interface: NIL means unknown, never unusable. With root it lets -l and
DEFAULT-IFACE apply the same link-type test that OPEN-CAPTURE will, instead of
blessing an interface the scan is about to refuse."
  (handler-case
      (let ((handle (pcap-open-live name :snaplen 64 :promisc nil :timeout-ms 1)))
        (unwind-protect (%pcap-datalink handle)
          (%pcap-close handle)))
    (pcap-error () nil)))

(defun check-datalink (handle name)
  "Signal UNUSABLE-INTERFACE unless HANDLE, open on NAME, carries Ethernet.
Every place that opens a handle to transmit or capture calls this, so a
non-Ethernet link is refused before a frame is built for it."
  (let ((reason (datalink-unusable-reason (%pcap-datalink handle))))
    (when reason
      (error 'unusable-interface :name name :reason reason))))

(defun link-local-p (ip-bytes)
  "True for IPv4 link-local 169.254.0.0/16."
  (and (= (aref ip-bytes 0) 169) (= (aref ip-bytes 1) 254)))

(defun iface-score (i)
  "Higher is better. Penalize link-local; small bonus for en0."
  (+ (if (link-local-p (iface-ip i)) 0 10)
     (if (string= (iface-name i) "en0") 1 0)))

(defun default-iface ()
  "Pick the best usable interface (up, has IPv4+MAC+netmask, non-loopback).
Prefers non-link-local addresses, then en0.

When we have the privilege to ask, candidates libpcap says are not Ethernet
are passed over too; otherwise OPEN-CAPTURE refuses the pick and points at -l,
which would have shown it as scannable."
  (let ((candidates (remove-if-not #'usable-iface-p (get-ifaces))))
    (unless candidates
      (error "No suitable network interface found (need an up, non-loopback iface with IPv4 and MAC)."))
    (let ((ethernet (remove-if (lambda (i)
                                 (let ((dlt (probe-datalink (iface-name i))))
                                   (and dlt (datalink-unusable-reason dlt))))
                               candidates)))
      (unless ethernet
        (error "No suitable network interface found: ~{~A~^, ~} ~
                ~[is~:;are~] up with IPv4 and a MAC, but libpcap reports ~
                a non-Ethernet link type for ~:*~[it~:;each~]."
               (mapcar #'iface-name candidates) (1- (length candidates))))
      (first (sort ethernet #'> :key #'iface-score)))))

(define-condition unusable-interface (error)
  ((name :initarg :name :reader unusable-interface-name)
   (reason :initarg :reason :reader unusable-interface-reason))
  (:report (lambda (c s)
             (format s "Cannot scan on ~A: ~A.~%Run 'arp-scan -l' to see which interfaces are usable."
                     (unusable-interface-name c) (unusable-interface-reason c))))
  (:documentation
   "Signalled when -i names an interface ARP cannot work on."))

(defun find-iface (name &key (needs '(:ip :netmask)) (ifaces (get-ifaces)))
  "Find the interface called NAME, or explain why it cannot be used.

DEFAULT-IFACE has always filtered on USABLE-IFACE-P; this did not, so naming a
tunnel explicitly got you as far as FORMAT-MAC before failing on a NIL hardware
address. NEEDS is passed through to IFACE-UNUSABLE-REASON. IFACES is the list
to search, so the smoke test can hand in synthetic interfaces instead of
depending on what the host happens to have.

Signals UNUSABLE-INTERFACE, which is exported along with its readers so a
library caller of SCAN-HOSTS can tell a bad interface from a permissions
failure."
  (let ((iface (find name ifaces :key #'iface-name :test #'string=)))
    (unless iface
      (error 'unusable-interface :name name :reason "no such interface"))
    (let ((reason (iface-unusable-reason iface :needs needs)))
      (when reason
        (error 'unusable-interface :name name :reason reason)))
    iface))

(defun format-ip (bytes)
  (format nil "~D.~D.~D.~D"
          (aref bytes 0) (aref bytes 1) (aref bytes 2) (aref bytes 3)))

(defun format-mac (bytes)
  (format nil "~2,'0x:~2,'0x:~2,'0x:~2,'0x:~2,'0x:~2,'0x"
          (aref bytes 0) (aref bytes 1) (aref bytes 2)
          (aref bytes 3) (aref bytes 4) (aref bytes 5)))

(defun list-interfaces ()
  "Print all network interfaces and their addresses.

Marks the ones a scan can actually use, and says why for the rest. Without that
the list is an inventory of everything the machine has, most of which --
tunnels, loopback, inactive adapters -- ARP cannot touch, and there is no way
to tell which is which. Run as root, it also asks libpcap for the link type, so
the marker agrees with what a scan will accept."
  (dolist (i (get-ifaces))
    (let ((reason (or (iface-unusable-reason i)
                      (let ((dlt (probe-datalink (iface-name i))))
                        (and dlt (datalink-unusable-reason dlt))))))
      (format t "~A~:[~; UP~]~:[~; LOOPBACK~]~:[~;  <- scannable~]~%"
              (iface-name i) (iface-up-p i) (iface-loopback-p i) (null reason))
      (when reason
        (format t "    not scannable: ~A~%" reason)))
    ;; An address can arrive without a netmask (ifa_netmask is allowed to be
    ;; null), and FIND-IFACE reports exactly that case -- so the listing it
    ;; sends the user to must not crash on it.
    (when (iface-ip i)
      (format t "    inet ~A~@[  netmask ~A~]~%"
              (format-ip (iface-ip i))
              (and (iface-netmask i) (format-ip (iface-netmask i)))))
    (when (iface-mac i)
      (format t "    ether ~A~%" (format-mac (iface-mac i))))))
