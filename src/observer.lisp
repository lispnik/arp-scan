(in-package #:arp-scan)

;;; Turning captured frames into host records, and noticing when the claims in
;;; those frames contradict each other.
;;;
;;; The scanner used to keep a bare IP -> MAC hash table and ignore any second
;;; reply for an address it had already resolved. That discarded exactly the
;;; case worth knowing about: a different MAC claiming an IP you have already
;;; resolved is what ARP cache poisoning looks like on the wire.
;;;
;;; Nothing here touches libpcap or prints anything -- it consumes byte vectors
;;; and calls back -- so the smoke test drives it directly without root.

(defparameter *mac-multi-ip-threshold* 5
  "How many distinct IPs one MAC may claim before we mention it. Legitimate
causes are common (see NOTE-MAC-CLAIM), so this only ever produces a remark.")

(defstruct host
  ip                                    ; 4-byte vector
  mac                                   ; 6-byte vector, the first MAC seen for IP
  vendor                                ; string or NIL
  (kind :global)                        ; :global | :randomized | :multicast
  rtt                                   ; seconds from request to reply, or NIL
  fingerprint                           ; probe-response bitmask string, or NIL
  first-seen                            ; universal time
  last-seen
  (reply-count 0)
  (request-count 0)
  padding                               ; raw Ethernet padding of the last frame
  (padding-kind :none)                  ; :none | :zero | :leak
  (alt-macs '()))                       ; ((mac . count) ...) for conflicting claims

(defstruct anomaly
  kind                                  ; :ip-conflict | :mac-multi-ip | :gratuitous
  time
  ip
  mac
  other-mac
  detail)

(defstruct observer
  (hosts (make-hash-table))             ; ip-u32 -> host
  (mac-claims (make-hash-table))        ; mac-u48 -> list of ip-u32
  (anomalies '())
  (reported-multi-ip (make-hash-table))  ; mac-u48 -> t, so we remark only once
  (send-times (make-hash-table))        ; ip-u32 -> monotonic seconds of last request
  scope                                 ; (lo . hi) u32 bounds, or NIL for anything
  on-host                               ; called with a HOST on first sighting
  on-anomaly)                           ; called with an ANOMALY as it is raised

(defun in-scope-p (obs ip-u32)
  "Whether IP-U32 is one this observer is meant to report on.

Because we now learn from ARP requests as well as replies, an unscoped observer
picks up every host chattering on the segment. That is the point in passive
mode, but during an explicit -r scan it would quietly return addresses outside
the range the user asked for."
  (let ((scope (observer-scope obs)))
    (or (null scope)
        (<= (car scope) ip-u32 (cdr scope)))))

(defun zero-bytes-p (v)
  (every #'zerop v))

;;; Padding
;;;
;;; An Ethernet frame is padded to 60 bytes, but the ARP payload ends at 42, so
;;; the responder's stack picks the remaining bytes. Most zero-fill. Some
;;; embedded stacks hand over whatever was in the buffer, which is worth seeing.
;;;
;;; This groups devices and occasionally exposes a leak; it is NOT OS
;;; identification. arp-fingerprint(1) does that properly, by sending a matrix
;;; of deliberately malformed probes and recording which ones draw a reply.

(defun classify-padding (padding)
  (cond ((or (null padding) (zerop (length padding))) :none)
        ((zero-bytes-p padding) :zero)
        (t :leak)))

(defun raise-anomaly (obs &rest args)
  (let ((a (apply #'make-anomaly :time (get-universal-time) args)))
    (push a (observer-anomalies obs))
    (when (observer-on-anomaly obs)
      (funcall (observer-on-anomaly obs) a))
    a))

(defun note-mac-claim (obs mac ip-u32)
  "Track which IPs MAC has claimed, and remark once if it claims a lot of them.

Deliberately worded as an observation: a router doing proxy ARP, a gateway
answering for off-subnet addresses, and a virtualization host bridging several
guests all legitimately answer for many addresses."
  (let* ((key (mac->u48 mac))
         (ips (gethash key (observer-mac-claims obs))))
    (unless (member ip-u32 ips)
      (push ip-u32 ips)
      (setf (gethash key (observer-mac-claims obs)) ips)
      (when (and (>= (length ips) *mac-multi-ip-threshold*)
                 (not (gethash key (observer-reported-multi-ip obs))))
        (setf (gethash key (observer-reported-multi-ip obs)) t)
        (raise-anomaly obs :kind :mac-multi-ip :mac mac
                           :detail (format nil "answers for ~D addresses (proxy ARP or a gateway will do this legitimately)"
                                           (length ips)))))))

(defun note-conflict (obs host mac)
  "Record that MAC claimed HOST's IP, which a different MAC already holds."
  (let ((entry (assoc mac (host-alt-macs host) :test #'equalp)))
    (if entry
        (incf (cdr entry))
        (progn
          (push (cons (copy-seq mac) 1) (host-alt-macs host))
          (raise-anomaly obs :kind :ip-conflict
                             :ip (host-ip host)
                             :mac (host-mac host)
                             :other-mac mac
                             :detail "two MACs claim this address")))))

(defun note-send (obs ip-u32 at)
  "Record that a request went out to IP-U32 at monotonic time AT."
  (setf (gethash ip-u32 (observer-send-times obs)) at))

(defun record-rtt (obs host key arrived-at)
  "Set HOST's round-trip time if this reply answers a request we sent.

Only the first measurement is kept: later replies to the same address are
usually unsolicited or answer a retry whose send time has been overwritten, and
either way they measure something other than what we asked."
  (let ((sent (gethash key (observer-send-times obs))))
    (when (and sent arrived-at (null (host-rtt host)) (>= arrived-at sent))
      (setf (host-rtt host) (- arrived-at sent)))))

(defun observe-frame (obs frame &optional arrived-at)
  "Fold one captured frame into OBS. Returns the HOST it concerns, or NIL."
  (multiple-value-bind (op spa sha tpa tha padding) (parse-arp frame)
    (declare (ignore tha))
    (when (and op
               (or (= op +arp-op-request+) (= op +arp-op-reply+))
               ;; An ARP probe (RFC 5227) announces 0.0.0.0 and tells us nothing
               ;; about who is at what address.
               (not (zero-bytes-p spa))
               (not (zero-bytes-p sha)))
      (let* ((key (ip->u32 spa))
             (now (get-universal-time))
             (host (gethash key (observer-hosts obs)))
             (new-p (null host)))
        (unless (in-scope-p obs key)
          (return-from observe-frame nil))
        (when new-p
          (setf host (make-host :ip spa :mac (copy-seq sha)
                                :vendor (oui-lookup sha)
                                :kind (mac-kind sha)
                                :first-seen now :last-seen now)
                (gethash key (observer-hosts obs)) host)
          ;; No NIC owns a multicast address, so a frame sourced from one is
          ;; malformed or forged either way.
          (when (multicast-mac-p sha)
            (raise-anomaly obs :kind :multicast-source :ip spa :mac sha
                               :detail "source MAC has the multicast bit set")))
        (setf (host-last-seen host) now)
        (if (= op +arp-op-reply+)
            (progn (incf (host-reply-count host))
                   (record-rtt obs host key arrived-at))
            (incf (host-request-count host)))
        ;; Padding is chosen by the peer's stack; keep the most recent one so
        ;; --padding shows something current.
        (when padding
          (setf (host-padding host) padding
                (host-padding-kind host) (classify-padding padding)))
        (unless (or new-p (equalp sha (host-mac host)))
          (note-conflict obs host sha))
        (note-mac-claim obs sha key)
        ;; A gratuitous ARP announces "this address is mine" with sender and
        ;; target equal. Routine at interface bring-up, notable mid-scan.
        (when (equalp spa tpa)
          (raise-anomaly obs :kind :gratuitous :ip spa :mac sha
                             :detail (if (= op +arp-op-reply+)
                                         "gratuitous ARP reply"
                                         "gratuitous ARP announcement")))
        (when (and new-p (observer-on-host obs))
          (funcall (observer-on-host obs) host))
        host))))

(defun observe-frames (obs frames)
  "Fold a drained batch of (frame . arrival-time) pairs into OBS."
  (loop for entry across frames
        do (observe-frame obs (car entry) (cdr entry))))

(defun observer-host-list (obs)
  "Hosts sorted by IP, which is the order every output format wants."
  (sort (alexandria:hash-table-values (observer-hosts obs))
        #'< :key (lambda (h) (ip->u32 (host-ip h)))))

(defun observer-seen-p (obs ip-u32)
  (nth-value 1 (gethash ip-u32 (observer-hosts obs))))
