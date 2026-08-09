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

(defconstant +arp-payload-length+ 28
  "Bytes of ARP payload for IPv4 over Ethernet; anything beyond is padding.")

(defconstant +ethertype-vlan+ #x8100)   ; 802.1Q
(defconstant +ethertype-qinq+ #x88a8)   ; 802.1ad, an outer tag

(defun subvector (frame start length)
  (let ((out (make-array length :element-type '(unsigned-byte 8))))
    (loop for i from 0 below length
          do (setf (aref out i) (aref frame (+ start i))))
    out))

(defun arp-offset (frame)
  "Offset of the ARP payload in FRAME, and the VLAN id if it was tagged.
Returns NIL when FRAME is not ARP at all.

A VLAN tag sits between the source MAC and the ethertype, pushing everything
after it out by four bytes, and 802.1ad can stack two. Reading the ethertype at
a fixed offset makes every tagged frame look like something other than ARP --
which on a trunk port means seeing nothing whatsoever."
  (let ((pos 12)
        (vlan nil))
    (loop repeat 2
          while (and (>= (length frame) (+ pos 4))
                     (let ((et (get-u16-be frame pos)))
                       (or (= et +ethertype-vlan+) (= et +ethertype-qinq+))))
          ;; The low 12 bits of the TCI are the VLAN id; the rest is priority
          ;; and the drop-eligible bit.
          do (setf vlan (logand #x0fff (get-u16-be frame (+ pos 2)))
                   pos (+ pos 4)))
    (when (and (>= (length frame) (+ pos 2))
               (= (get-u16-be frame pos) +ethertype-arp+))
      (values (+ pos 2) vlan))))

(defun parse-arp (frame)
  "Parse any ARP frame, request or reply, tagged or not.

Returns (values op spa sha tpa tha padding vlan), or NIL if FRAME is not ARP.
PADDING is the Ethernet filler past the ARP payload, or NIL when the capture was
too short to include any. Callers get the padding because the sending stack
chooses it and some devices leak buffer contents there."
  (multiple-value-bind (arp vlan) (arp-offset frame)
    (when (and arp (>= (length frame) (+ arp +arp-payload-length+)))
      (let ((end (+ arp +arp-payload-length+)))
        (values (get-u16-be frame (+ arp 6))    ; op
                (subvector frame (+ arp 14) 4)  ; spa: sender protocol address
                (subvector frame (+ arp 8) 6)   ; sha: sender hardware address
                (subvector frame (+ arp 24) 4)  ; tpa: target protocol address
                (subvector frame (+ arp 18) 6)  ; tha: target hardware address
                (when (> (length frame) end)
                  (subvector frame end (- (length frame) end)))
                vlan)))))

(defun parse-arp-reply (frame)
  "If FRAME is an ARP reply, return (values sender-ip sender-mac), else NIL."
  (multiple-value-bind (op spa sha) (parse-arp frame)
    (when (and op (= op +arp-op-reply+))
      (values spa sha))))

;;; Wake-on-LAN
;;;
;;; A magic packet is six 0xFF bytes followed by the target MAC repeated
;;; sixteen times. Sent here as a raw Ethernet frame with ethertype 0x0842
;;; rather than wrapped in UDP: we already have link-layer injection, and this
;;; way there is no IP stack, no port and no routing involved -- it just has to
;;; reach the segment.

(defconstant +ethertype-wol+ #x0842)

(defun build-wol-packet (src-mac target-mac)
  "Build a Wake-on-LAN magic packet frame addressed to TARGET-MAC."
  (let ((frame (make-array (+ 14 102) :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
    (copy-into frame 0 target-mac)
    (copy-into frame 6 src-mac)
    (set-u16-be frame 12 +ethertype-wol+)
    (loop for i from 14 below 20 do (setf (aref frame i) #xff))
    (loop for rep from 0 below 16
          do (copy-into frame (+ 20 (* rep 6)) target-mac))
    frame))

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

(define-condition invalid-target (error)
  ((text :initarg :text :reader invalid-target-text)
   (reason :initarg :reason :reader invalid-target-reason))
  (:report (lambda (c s)
             (format s "Bad target ~S: ~A"
                     (invalid-target-text c) (invalid-target-reason c))))
  (:documentation
   "Signalled for input a user typed, so MAIN can report it as a usage problem
rather than letting a raw type error out of PARSE-INTEGER or AREF reach them."))

(defun bad-target (text reason &rest args)
  (error 'invalid-target :text text :reason (apply #'format nil reason args)))

(defun parse-ip (s)
  "Parse a dotted-quad string to a 4-byte vector.

Validates rather than trusting: unchecked, \"999.1.1.0\" reaches AREF and dies
with a type error about (UNSIGNED-BYTE 8), which tells the user nothing about
what they typed."
  (let ((octets '())
        (start 0))
    (dotimes (i (1+ (length s)))
      (when (or (= i (length s)) (char= (char s i) #\.))
        (when (= start i)
          (bad-target s "empty octet"))
        (let ((piece (subseq s start i)))
          (unless (every #'digit-char-p piece)
            (bad-target s "~S is not a number" piece))
          (let ((v (parse-integer piece :junk-allowed t)))
            (unless (and v (<= 0 v 255))
              (bad-target s "octet ~A is out of range 0-255" piece))
            (push v octets)))
        (setf start (1+ i))))
    (setf octets (nreverse octets))
    (unless (= 4 (length octets))
      (bad-target s "expected 4 octets, got ~D" (length octets)))
    (make-array 4 :element-type '(unsigned-byte 8) :initial-contents octets)))

(defun prefix->mask (prefix)
  (if (zerop prefix)
      0
      (logand #xffffffff (ash #xffffffff (- 32 prefix)))))

(defun cidr-range (cidr)
  "Given e.g. \"192.168.1.0/24\", return (values first-u32 last-u32).
Excludes network and broadcast for prefixes <= 30.

The prefix bound is not decoration. Unchecked, /99 makes (ASH #xFFFFFFFF -67)
zero, the mask vanishes, and the range becomes the whole of IPv4 -- which the
caller then tries to walk, so a single mistyped digit turns into 4.3 billion
addresses and an exhausted heap."
  (let ((slash (position #\/ cidr)))
    (unless slash
      (bad-target cidr "expected a prefix, as in ~A/24" cidr))
    (let ((prefix-s (subseq cidr (1+ slash))))
      (unless (and (plusp (length prefix-s)) (every #'digit-char-p prefix-s))
        (bad-target cidr "prefix ~S is not a number" prefix-s))
      (let ((prefix (parse-integer prefix-s)))
        (unless (<= 0 prefix 32)
          (bad-target cidr "prefix /~D is out of range 0-32" prefix))
        (let* ((ip (ip->u32 (parse-ip (subseq cidr 0 slash))))
               (mask (prefix->mask prefix))
               (net (logand ip mask))
               (bcast (logior net (logand #xffffffff (lognot mask)))))
          (if (<= prefix 30)
              (values (1+ net) (1- bcast))
              (values net bcast)))))))

;;; Target sets
;;;
;;; A scan is a list of (lo . hi) u32 segments rather than one range, so several
;;; disjoint pieces of address space can be asked about in one run. Segments are
;;; merged, which both removes double-sends where the user's specs overlap and
;;; keeps the walk in address order.
;;;
;;; They stay as bounds, never expanded into addresses: the walk is what keeps a
;;; wide range from allocating (see SEND-PASS).

(defun parse-target (spec)
  "Parse one target: a CIDR block, an address range, or a single address.

  192.168.1.0/24            a block
  192.168.1.10-192.168.1.50 a range
  192.168.1.10-50           the same, abbreviated to the last octet
  192.168.1.5               one address

Returns (values lo hi)."
  (let ((spec (string-trim '(#\Space #\Tab) spec)))
    (when (zerop (length spec))
      (bad-target spec "empty target"))
    (cond
      ((find #\/ spec) (cidr-range spec))
      ((find #\- spec)
       (let* ((dash (position #\- spec))
              (lo-s (subseq spec 0 dash))
              (hi-s (subseq spec (1+ dash)))
              (lo (ip->u32 (parse-ip lo-s)))
              ;; A bare number after the dash is the last octet, so
              ;; 192.168.1.10-50 does not have to be written out twice.
              (hi (if (find #\. hi-s)
                      (ip->u32 (parse-ip hi-s))
                      (progn
                        (unless (and (plusp (length hi-s))
                                     (every #'digit-char-p hi-s))
                          (bad-target spec "~S is neither an address nor an octet" hi-s))
                        (let ((n (parse-integer hi-s)))
                          (unless (<= 0 n 255)
                            (bad-target spec "octet ~D is out of range 0-255" n))
                          (logior (logandc2 lo 255) n))))))
         (when (> lo hi)
           (bad-target spec "range runs backwards"))
         (values lo hi)))
      (t (let ((n (ip->u32 (parse-ip spec))))
           (values n n))))))

(defun merge-segments (segments)
  "Sort and coalesce (lo . hi) pairs so nothing is asked twice."
  (let ((sorted (sort (copy-list segments) #'< :key #'car))
        (out '()))
    (dolist (seg sorted (nreverse out))
      (let ((prev (first out)))
        ;; 1+ so segments that merely abut are joined too, not just overlaps.
        (if (and prev (<= (car seg) (1+ (cdr prev))))
            (setf (cdr prev) (max (cdr prev) (cdr seg)))
            (push (cons (car seg) (cdr seg)) out))))))

(defun parse-targets (spec)
  "Parse a comma-separated list of targets into merged segments."
  (let ((segments '())
        (start 0))
    (dotimes (i (1+ (length spec)))
      (when (or (= i (length spec)) (char= (char spec i) #\,))
        (let ((piece (string-trim '(#\Space #\Tab) (subseq spec start i))))
          (unless (zerop (length piece))
            (multiple-value-bind (lo hi) (parse-target piece)
              (push (cons lo hi) segments))))
        (setf start (1+ i))))
    (unless segments
      (bad-target spec "no targets"))
    (merge-segments segments)))

(defun segments-count (segments)
  (reduce #'+ segments :key (lambda (s) (1+ (- (cdr s) (car s))))))

(defun in-segments-p (segments u32)
  (loop for (lo . hi) in segments
          thereis (<= lo u32 hi)))

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
