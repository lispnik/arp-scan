(in-package #:arp-scan)

;;; Look here  https://datatracker.ietf.org/doc/html/rfc826

;;; Ethernet + ARP framing.
;;;
;;; Ethernet header (14 bytes): dst-mac(6) src-mac(6) ethertype(2)
;;; ARP packet  (28 bytes for IPv4):
;;;   htype(2)=1 ptype(2)=0x0800 hlen(1)=6 plen(1)=4 op(2)
;;;   sha(6) spa(4) tha(6) tpa(4)
;;; We pad to 60 bytes so the frame meets the Ethernet minimum.

(defconstant +ethertype-arp+ #x0806)
(defconstant +arp-op-request+ 1)
(defconstant +arp-op-reply+   2)

(defun set-u16-be (vec offset value)
  (setf (aref vec offset)        (ldb (byte 8 8) value)
        (aref vec (1+ offset))   (ldb (byte 8 0) value)))

(defun get-u16-be (vec offset)
  (logior (ash (aref vec offset) 8) (aref vec (1+ offset))))

(defun copy-into (dst dst-off src)
  (loop for i from 0 below (length src)
        do (setf (aref dst (+ dst-off i)) (aref src i))))

(defun build-arp-request (src-mac src-ip target-ip)
  "Build a 60-byte broadcast ARP request frame."
  (let ((frame (make-array 60 :element-type '(unsigned-byte 8) :initial-element 0))
        (bcast #(#xff #xff #xff #xff #xff #xff)))
    ;; Ethernet header
    (copy-into frame 0 bcast)
    (copy-into frame 6 src-mac)
    (set-u16-be frame 12 +ethertype-arp+)
    ;; ARP payload at offset 14
    (set-u16-be frame 14 1)             ; htype: Ethernet
    (set-u16-be frame 16 #x0800)        ; ptype: IPv4
    (setf (aref frame 18) 6             ; hlen
          (aref frame 19) 4)            ; plen
    (set-u16-be frame 20 +arp-op-request+)
    (copy-into frame 22 src-mac)        ; sha
    (copy-into frame 28 src-ip)         ; spa
    ;; tha left as zeros
    (copy-into frame 38 target-ip)      ; tpa
    frame))

(defconstant +arp-payload-end+ 42
  "Offset just past the ARP payload; anything beyond is Ethernet padding.")

(defun subvector (frame start length)
  (let ((out (make-array length :element-type '(unsigned-byte 8))))
    (loop for i from 0 below length
          do (setf (aref out i) (aref frame (+ start i))))
    out))

(defun parse-arp (frame)
  "Parse any ARP frame, request or reply.

Returns (values op spa sha tpa tha padding), or NIL if FRAME is not ARP.
PADDING is the Ethernet filler past the 42-byte ARP payload, or NIL when the
capture was too short to include any. Callers get the padding because the
sending stack chooses it and some devices leak buffer contents there."
  (when (and (>= (length frame) +arp-payload-end+)
             (= (get-u16-be frame 12) +ethertype-arp+))
    (values (get-u16-be frame 20)             ; op
            (subvector frame 28 4)            ; spa: sender protocol address
            (subvector frame 22 6)            ; sha: sender hardware address
            (subvector frame 38 4)            ; tpa: target protocol address
            (subvector frame 32 6)            ; tha: target hardware address
            (when (> (length frame) +arp-payload-end+)
              (subvector frame +arp-payload-end+
                         (- (length frame) +arp-payload-end+))))))

(defun parse-arp-reply (frame)
  "If FRAME is an ARP reply, return (values sender-ip sender-mac), else NIL."
  (multiple-value-bind (op spa sha) (parse-arp frame)
    (when (and op (= op +arp-op-reply+))
      (values spa sha))))

;;; MAC address semantics
;;;
;;; The two low bits of the first octet carry meaning, and both matter to us:
;;;
;;;   bit 0 (0x01) -- group/multicast. Legal as a *destination*, never as a
;;;                   source: no real NIC owns a multicast address, so a frame
;;;                   claiming one is malformed or forged.
;;;   bit 1 (0x02) -- locally administered. The address was assigned by software
;;;                   rather than burned in by a manufacturer, which today
;;;                   usually means privacy randomization -- iOS and Android
;;;                   rotate one per SSID. There is no vendor to look up, and
;;;                   printing an empty vendor column implies we failed rather
;;;                   than that the question has no answer.

(defun mac->u48 (mac)
  (loop with n = 0
        for b across mac
        do (setf n (logior (ash n 8) b))
        finally (return n)))

(defun multicast-mac-p (mac)
  (logbitp 0 (aref mac 0)))

(defun locally-administered-p (mac)
  (logbitp 1 (aref mac 0)))

(defun mac-kind (mac)
  "One of :global, :randomized, or :multicast."
  (cond ((multicast-mac-p mac) :multicast)
        ((locally-administered-p mac) :randomized)
        (t :global)))

;;; IP / CIDR helpers

(defun ip->u32 (bytes)
  (logior (ash (aref bytes 0) 24)
          (ash (aref bytes 1) 16)
          (ash (aref bytes 2) 8)
          (aref bytes 3)))

(defun u32->ip (n)
  (let ((b (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref b 0) (ldb (byte 8 24) n)
          (aref b 1) (ldb (byte 8 16) n)
          (aref b 2) (ldb (byte 8 8)  n)
          (aref b 3) (ldb (byte 8 0)  n))
    b))

(defun parse-ip (s)
  "Parse a dotted-quad string to a 4-byte vector."
  (let ((bytes (make-array 4 :element-type '(unsigned-byte 8)))
        (start 0)
        (idx 0))
    (dotimes (i (length s))
      (when (char= (char s i) #\.)
        (setf (aref bytes idx) (parse-integer s :start start :end i)
              start (1+ i)
              idx (1+ idx))))
    (setf (aref bytes 3) (parse-integer s :start start))
    bytes))

(defun prefix->mask (prefix)
  (if (zerop prefix)
      0
      (logand #xffffffff (ash #xffffffff (- 32 prefix)))))

(defun cidr-range (cidr)
  "Given e.g. \"192.168.1.0/24\", return (values first-u32 last-u32).
Excludes network and broadcast for prefixes <= 30."
  (let* ((slash (position #\/ cidr))
         (ip-s (subseq cidr 0 slash))
         (prefix (parse-integer cidr :start (1+ slash)))
         (ip (ip->u32 (parse-ip ip-s)))
         (mask (prefix->mask prefix))
         (net (logand ip mask))
         (bcast (logior net (logand #xffffffff (lognot mask)))))
    (if (<= prefix 30)
        (values (1+ net) (1- bcast))
        (values net bcast))))

(defun subnet-range-from-iface (iface)
  "Return (values first-u32 last-u32) for the iface's local subnet."
  (let* ((ip (ip->u32 (iface-ip iface)))
         (mask (ip->u32 (iface-netmask iface)))
         (prefix (logcount mask))
         (net (logand ip mask))
         (bcast (logior net (logand #xffffffff (lognot mask)))))
    (if (<= prefix 30)
        (values (1+ net) (1- bcast))
        (values net bcast))))
