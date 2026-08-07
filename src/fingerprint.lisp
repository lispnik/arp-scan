(in-package #:arp-scan)

;;; Active stack fingerprinting.
;;;
;;; The padding classifier in observer.lisp is the passive, weak version of this
;;; -- it reads whatever the peer happened to leave in the Ethernet filler. This
;;; is the real technique, the one arp-fingerprint(1) uses: send a series of
;;; deliberately malformed ARP requests and record which ones a host bothers to
;;; answer. Stacks disagree sharply about what is worth replying to, so the
;;; pattern of answers separates them.
;;;
;;; What we DON'T do is ship a signature table mapping patterns to OS names. A
;;; credible one has to be built by testing against known hardware, and inventing
;;; entries would produce confident output that happens to be fiction. So this
;;; reports the raw bit pattern and groups hosts that share one. That is directly
;;; useful -- devices with identical patterns run the same stack, which is often
;;; the actual question -- and it leaves an honest foundation for a table built
;;; from measurements later.

(defstruct probe
  name
  description
  overrides)                            ; plist passed to BUILD-ARP-PROBE

(defparameter *probes*
  (list
   (make-probe :name "normal" :description "well-formed request (the control)"
               :overrides '())
   (make-probe :name "hrd" :description "invalid hardware type"
               :overrides '(:htype #xffff))
   (make-probe :name "pro" :description "invalid protocol type"
               :overrides '(:ptype #xffff))
   (make-probe :name "hln" :description "hardware address length 0"
               :overrides '(:hlen 0))
   (make-probe :name "pln" :description "protocol address length 0"
               :overrides '(:plen 0))
   (make-probe :name "op" :description "undefined opcode"
               :overrides '(:op 255))
   (make-probe :name "spa0" :description "sender protocol address 0.0.0.0"
               :overrides '(:spa #(0 0 0 0)))
   (make-probe :name "dst" :description "near-broadcast destination MAC"
               :overrides '(:dst #(#xff #xff #xff #xff #xff #xfe)))
   (make-probe :name "shabc" :description "sender hardware address is broadcast"
               :overrides '(:sha #(#xff #xff #xff #xff #xff #xff))))
  "The probe matrix. Order is fixed: it defines bit order in the fingerprint, so
appending is safe but reordering or removing invalidates every recorded pattern.")

(defun build-arp-probe (src-mac src-ip target-ip
                        &key (htype 1) (ptype #x0800) (hlen 6) (plen 4)
                             (op +arp-op-request+) dst sha spa)
  "Build an ARP frame with any field overridden, however invalid.

BUILD-ARP-REQUEST deliberately offers no way to do this; malformed frames are
only ever wanted here, and letting the normal scan path emit them by accident
would be a bad trade."
  (let ((frame (make-array 60 :element-type '(unsigned-byte 8) :initial-element 0))
        (sender-mac (or sha src-mac))
        (sender-ip (or spa src-ip)))
    (copy-into frame 0 (or dst #(#xff #xff #xff #xff #xff #xff)))
    (copy-into frame 6 src-mac)
    (set-u16-be frame 12 +ethertype-arp+)
    (set-u16-be frame 14 htype)
    (set-u16-be frame 16 ptype)
    (setf (aref frame 18) hlen
          (aref frame 19) plen)
    (set-u16-be frame 20 op)
    (copy-into frame 22 sender-mac)
    (copy-into frame 28 sender-ip)
    (copy-into frame 38 target-ip)
    frame))

(defun probe-frame (probe src-mac src-ip target-ip)
  (apply #'build-arp-probe src-mac src-ip target-ip (probe-overrides probe)))

(defun probe-wait-for (hosts)
  "How long to wait on each probe, derived from the round trips already measured.

A fixed wait is the wrong tool here. Wi-Fi power saving parks frames at the AP
until the next DTIM beacon, which we have measured at over 300 ms on real
devices -- against a 250 ms wait those hosts score 0 on every probe, including
the well-formed control, and the resulting pattern is a description of our
timeout rather than of their stack. Scale off the slowest observed reply, with a
floor for quiet networks and a ceiling so one pathological host cannot stall the
whole run."
  (let ((slowest (reduce #'max (remove nil (mapcar #'host-rtt hosts))
                         :initial-value 0)))
    (max 0.25 (min 2.0 (* 3 slowest)))))

(defun fingerprint-hosts (handle cap iface hosts &key per-probe-wait)
  "Probe each host in HOSTS and set its FINGERPRINT to a bit pattern.

One bit per entry in *PROBES*, in order, `1' meaning the host replied. Probes go
out unicast to one host at a time and each is waited on separately, because the
whole measurement is which specific probe drew the answer -- batching would blur
that."
  (let ((src-mac (iface-mac iface))
        (src-ip (iface-ip iface))
        (per-probe-wait (or per-probe-wait (probe-wait-for hosts))))
    (dolist (host hosts)
      (let ((bits (make-string-output-stream)))
        (dolist (probe *probes*)
          ;; Discard anything already queued so the wait below can only see
          ;; replies drawn by this probe.
          (capture-drain cap)
          (pcap-sendpacket handle (probe-frame probe src-mac src-ip (host-ip host)))
          (let ((deadline (+ (capture-now) per-probe-wait))
                (answered nil))
            (loop until (or answered (>= (capture-now) deadline))
                  do (loop for entry across (capture-drain cap)
                           do (multiple-value-bind (op spa sha)
                                  (parse-arp (car entry))
                                (when (and op (= op +arp-op-reply+)
                                           (equalp spa (host-ip host))
                                           (equalp sha (host-mac host)))
                                  (setf answered t))))
                     (unless answered (sleep 0.005)))
            (write-char (if answered #\1 #\0) bits)))
        (setf (host-fingerprint host) (get-output-stream-string bits))))
    hosts))

(defun fingerprint-reliable-p (host)
  "Whether a host's pattern is worth believing.

The first probe is a well-formed request. A host that ignores that but answers
malformed ones has almost certainly not revealed anything about its stack -- it
was asleep or slow when the control went out, and every bit is suspect."
  (let ((fp (host-fingerprint host)))
    (and fp (plusp (length fp)) (char= (char fp 0) #\1))))

(defun print-fingerprints (hosts &key (stream *standard-output*))
  "Report fingerprints, grouped so hosts running the same stack sit together."
  (let* ((measured (remove nil hosts :key #'host-fingerprint))
         (reliable (remove-if-not #'fingerprint-reliable-p measured))
         (suspect (remove-if #'fingerprint-reliable-p measured))
         (groups (make-hash-table :test 'equal)))
    (when measured
      (format stream "~%Fingerprints (bit order: ~{~A~^ ~})~%"
              (mapcar #'probe-name *probes*))
      (dolist (probe *probes*)
        (format stream "  ~8A ~A~%" (probe-name probe) (probe-description probe)))
      (dolist (host reliable)
        (push host (gethash (host-fingerprint host) groups)))
      (format stream "~%")
      (maphash (lambda (pattern members)
                 (format stream "  ~A  (~D host~:P)~%" pattern (length members))
                 (dolist (host (nreverse members))
                   (format stream "      ~16A ~17A ~A~%"
                           (format-ip (host-ip host))
                           (format-mac (host-mac host))
                           (host-vendor-text host))))
               groups)
      (when suspect
        (format stream "~%  Unreliable -- no answer to the well-formed control probe,~%~
                          so these patterns describe our timeout, not their stack:~%")
        (dolist (host suspect)
          (format stream "      ~A  ~16A ~17A ~A~%"
                  (host-fingerprint host)
                  (format-ip (host-ip host))
                  (format-mac (host-mac host))
                  (host-vendor-text host))))
      (format stream "~%Hosts sharing a pattern run the same ARP implementation.~%~
                      No OS names are claimed: mapping patterns to systems needs a~%~
                      signature table built from known hardware, which this does not ship.~%"))
    (force-output stream)
    measured))
