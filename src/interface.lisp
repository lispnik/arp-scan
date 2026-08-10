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

(defun usable-iface-p (i)
  (and (iface-up-p i)
       (not (iface-loopback-p i))
       (iface-ip i)
       (iface-mac i)
       (iface-netmask i)))

(defun link-local-p (ip-bytes)
  "True for IPv4 link-local 169.254.0.0/16."
  (and (= (aref ip-bytes 0) 169) (= (aref ip-bytes 1) 254)))

(defun iface-score (i)
  "Higher is better. Penalize link-local; small bonus for en0."
  (+ (if (link-local-p (iface-ip i)) 0 10)
     (if (string= (iface-name i) "en0") 1 0)))

(defun default-iface ()
  "Pick the best usable interface (up, has IPv4+MAC+netmask, non-loopback).
Prefers non-link-local addresses, then en0."
  (let ((candidates (remove-if-not #'usable-iface-p (get-ifaces))))
    (unless candidates
      (error "No suitable network interface found (need an up, non-loopback iface with IPv4 and MAC)."))
    (first (sort candidates #'> :key #'iface-score))))

(define-condition unusable-interface (error)
  ((name :initarg :name :reader unusable-interface-name)
   (reason :initarg :reason :reader unusable-interface-reason))
  (:report (lambda (c s)
             (format s "Cannot scan on ~A: ~A.~%Run 'arp-scan -l' to see which interfaces are usable."
                     (unusable-interface-name c) (unusable-interface-reason c))))
  (:documentation
   "Signalled when -i names an interface ARP cannot work on."))

(defun find-iface (name)
  "Find the interface called NAME, or explain why it cannot be scanned.

DEFAULT-IFACE has always filtered on USABLE-IFACE-P; this did not, so naming a
tunnel explicitly got you as far as FORMAT-MAC before failing on a NIL hardware
address. The checks are ordered most-specific first so the message names the
actual obstacle rather than the first missing field."
  (let ((iface (find name (get-ifaces) :key #'iface-name :test #'string=)))
    (cond
      ((null iface)
       (error 'unusable-interface :name name :reason "no such interface"))
      ((iface-loopback-p iface)
       (error 'unusable-interface :name name
              :reason "it is the loopback interface, which has no peers to ask"))
      ((null (iface-mac iface))
       ;; Built with FORMAT so the line continuations are processed; a bare
       ;; string literal would carry the tildes into the slot verbatim.
       (error 'unusable-interface :name name
              :reason (format nil "it has no hardware address, so it is not ~
                                   Ethernet. Point-to-point links such as VPN ~
                                   and utun tunnels carry no Ethernet header ~
                                   for an ARP frame to live in")))
      ((null (iface-ip iface))
       (error 'unusable-interface :name name :reason "it has no IPv4 address"))
      ((null (iface-netmask iface))
       (error 'unusable-interface :name name :reason "it has no IPv4 netmask"))
      ((not (iface-up-p iface))
       (error 'unusable-interface :name name :reason "it is down"))
      (t iface))))

(defun format-ip (bytes)
  (format nil "~D.~D.~D.~D"
          (aref bytes 0) (aref bytes 1) (aref bytes 2) (aref bytes 3)))

(defun format-mac (bytes)
  (format nil "~2,'0x:~2,'0x:~2,'0x:~2,'0x:~2,'0x:~2,'0x"
          (aref bytes 0) (aref bytes 1) (aref bytes 2)
          (aref bytes 3) (aref bytes 4) (aref bytes 5)))

(defun list-interfaces ()
  "Print all network interfaces and their addresses.

Marks the ones a scan can actually use. Without that the list is a inventory of
everything the machine has, most of which -- tunnels, loopback, inactive
adapters -- ARP cannot touch, and there is no way to tell which is which."
  (dolist (i (get-ifaces))
    (format t "~A~:[~; UP~]~:[~; LOOPBACK~]~:[~;  <- scannable~]~%"
            (iface-name i) (iface-up-p i) (iface-loopback-p i)
            (usable-iface-p i))
    (when (iface-ip i)
      (format t "    inet ~A  netmask ~A~%"
              (format-ip (iface-ip i))
              (format-ip (iface-netmask i))))
    (when (iface-mac i)
      (format t "    ether ~A~%" (format-mac (iface-mac i))))))
