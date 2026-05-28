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

(defun parse-arp-reply (frame)
  "If FRAME is an ARP reply, return (values sender-ip sender-mac), else NIL."
  (when (and (>= (length frame) 42)
             (= (get-u16-be frame 12) +ethertype-arp+)
             (= (get-u16-be frame 20) +arp-op-reply+))
    (let ((sha (make-array 6 :element-type '(unsigned-byte 8)))
          (spa (make-array 4 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 6 do (setf (aref sha i) (aref frame (+ 22 i))))
      (loop for i from 0 below 4 do (setf (aref spa i) (aref frame (+ 28 i))))
      (values spa sha))))

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
