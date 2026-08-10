(in-package #:arp-scan)

;;; Driving a scan.
;;;
;;; Capture runs on its own thread (see capture.lisp) rather than being polled
;;; between sends, so replies arriving while this thread is asleep are no longer
;;; at the mercy of the kernel buffer. That is what makes passive and watch
;;; modes worth having: both are mostly listening.
;;;
;;; Two handles, not one: a pcap_t cannot be used from two threads at once, so
;;; the capture thread owns one exclusively and sending happens on a second.

(defun now-internal ()
  (/ (get-internal-real-time) internal-time-units-per-second 1.0d0))

(defun capture-filter (src-mac)
  "BPF filter for the capture handle.

Excluding our own source MAC matters once requests are parsed as well as
replies: our outgoing broadcasts would otherwise come straight back and
register us as a discovered host. Doing it in the kernel beats filtering in
Lisp.

The `vlan' arm is not redundant. libpcap's `arp' primitive tests the ethertype
at a fixed offset, so it never matches a tagged frame -- on a trunk port the
plain filter yields nothing at all."
  (format nil "(arp or (vlan and arp)) and not ether src ~A" (format-mac src-mac)))

(defconstant +dlt-en10mb+ 1
  "libpcap's link type for Ethernet, the only one carrying ARP.")

(defun open-capture (iface)
  "Open the listening handle, filtered and ready for the capture thread."
  (let ((handle (pcap-open-live (iface-name iface)
                                ;; 96 covers the 60-byte frame plus slack, which
                                ;; is what lets us keep the trailing padding.
                                :snaplen 96 :promisc nil :timeout-ms 50)))
    (handler-case
        (progn
          ;; FIND-IFACE rejects anything without a hardware address, which
          ;; catches tunnels already. This asks libpcap directly, so a device
          ;; that has a MAC but hands us something other than Ethernet frames
          ;; is caught too, rather than being parsed as though it were.
          (let ((dlt (%pcap-datalink handle)))
            (unless (= dlt +dlt-en10mb+)
              (error 'unusable-interface :name (iface-name iface)
                     :reason (format nil "libpcap reports link type ~D, not Ethernet (~D), ~
                                          so frames on it carry no ARP"
                                     dlt +dlt-en10mb+))))
          (pcap-setfilter handle (capture-filter (iface-mac iface)))
          handle)
      (error (e) (%pcap-close handle) (error e)))))

(defun pump (cap obs &optional (seconds 0))
  "Fold everything the capture thread has queued into OBS, listening for a
further SECONDS."
  (let ((deadline (+ (now-internal) seconds)))
    (loop (observe-frames obs (capture-drain cap))
          (when (>= (now-internal) deadline) (return))
          (sleep (min 0.05 (max 0.001 (- deadline (now-internal))))))
    ;; One last sweep, so frames that landed during the final sleep are not left
    ;; sitting in the queue.
    (observe-frames obs (capture-drain cap))))

(defun send-pass (send-fn cap obs segments per-host-delay-us &key skip-answered)
  "Ask every address in SEGMENTS, draining replies as we go. Returns how many
were asked. With SKIP-ANSWERED, addresses that already replied are passed over,
which is what makes each retry cheaper than the last.

SEGMENTS is a list of (lo . hi) u32 bounds, so a scan can cover several disjoint
pieces of address space in one run.

SEND-FN takes a target as a u32 and transmits. Passing it in rather than a pcap
handle is what lets the smoke test drive this loop with a stub, no NIC and no
root -- the capture queue already deals in plain byte vectors.

The range is walked rather than listed. Materializing it cost one cons per
address before a single packet went out -- fine for a /24, 16 million for a /8,
and the mechanism by which a bad prefix used to exhaust the heap.

The send is stamped just *before* the frame goes out, on the same monotonic
clock the capture thread stamps arrivals with, so the difference is a real round
trip rather than a comparison across two clock domains. Stamping afterwards
loses any reply that lands between the transmit returning and the stamp being
taken -- RECORD-RTT discards an arrival earlier than its send -- which costs a
few microseconds of accuracy to avoid dropping measurements outright."
  (let ((sent 0))
    (loop for (lo . hi) in segments
          do (loop for u32 from lo to hi
                   unless (and skip-answered (observer-seen-p obs u32))
                     do (note-send obs u32 (capture-now))
                        (funcall send-fn u32)
                        (observe-frames obs (capture-drain cap))
                        (incf sent)
                        (when (plusp per-host-delay-us)
                          (sleep (/ per-host-delay-us 1.0d6)))))
    sent))

(defun run-passes (send-fn cap obs segments
                   &key (per-host-delay-us 1000) (wait-seconds 2) (retry 2))
  "The scan loop proper: one pass over SEGMENTS, then up to RETRY further
passes over whoever stayed silent, listening WAIT-SECONDS after each.

Holds no handles and opens nothing, so it is exercised directly by the smoke
test. Returns OBS."
  (send-pass send-fn cap obs segments per-host-delay-us)
  (pump cap obs wait-seconds)
  ;; Retries cover only the silent addresses, so each pass is cheaper than the
  ;; one before it. Stop early once a pass has nothing left to ask.
  (loop repeat retry
        while (plusp (send-pass send-fn cap obs segments per-host-delay-us
                                :skip-answered t))
        do (pump cap obs wait-seconds))
  obs)

(defun make-scan-observer (format padding anomalies-only &key on-anomaly-hook)
  "An observer wired for streaming output under text format; silent otherwise,
since json and csv cannot be emitted until the run is complete."
  (make-observer
   :on-host (when (and (eq format :text) (not anomalies-only))
              (lambda (host) (print-host-text host :padding padding)))
   :on-anomaly (lambda (a)
                 (when (eq format :text) (print-anomaly-text a))
                 (when on-anomaly-hook (anomaly-hook on-anomaly-hook a)))))

(defun scan-once (&key iface obs cidr passive (per-host-delay-us 1000)
                       (wait-seconds 2) (retry 2) fingerprint
                       (progress *standard-output*) header-p)
  "Run one set of passes against IFACE, folding results into OBS.

With PASSIVE, nothing is transmitted: we only listen for WAIT-SECONDS. Otherwise
requests go out across the range, then RETRY further passes cover whoever has
not answered. Banners go to PROGRESS, which callers point away from stdout when
stdout has to stay machine-readable."
  (let* ((src-mac (iface-mac iface))
         (src-ip (iface-ip iface))
         (capture-handle (open-capture iface))
         (cap nil)
         (send-handle nil))
    (unwind-protect
         (progn
           (setf cap (start-capture capture-handle))
           (cond
             (passive
              (format progress "Listening on ~A (~A, ~A) for ~D second~:P; sending nothing~%"
                      (iface-name iface) (format-ip src-ip) (format-mac src-mac)
                      wait-seconds)
              (when header-p
                (format progress *text-row-fmt* "IP" "MAC" "Vendor"))
              (force-output progress)
              (pump cap obs wait-seconds))
             (t
              (setf send-handle (pcap-open-live (iface-name iface)
                                                :snaplen 96 :promisc nil :timeout-ms 50))
              (let ((segments (if cidr
                                  (parse-targets cidr)
                                  (multiple-value-bind (lo hi)
                                      (subnet-range-from-iface iface)
                                    (list (cons lo hi))))))
                ;; Report only what was asked for. Ambient ARP chatter from
                ;; outside the range is still captured -- it just is not ours
                ;; to report here. Use --passive for that.
                (setf (observer-scope obs) segments)
                (format progress "Scanning ~{~A~^, ~} (~:D ~A) on ~A (~A, ~A)~%"
                        (mapcar (lambda (s)
                                  (if (= (car s) (cdr s))
                                      (format-ip (u32->ip (car s)))
                                      (format nil "~A - ~A"
                                              (format-ip (u32->ip (car s)))
                                              (format-ip (u32->ip (cdr s))))))
                                segments)
                        (segments-count segments)
                        ;; ~P would give "addresss"; the plural of address is
                        ;; not formed by adding an s.
                        (if (= 1 (segments-count segments)) "address" "addresses")
                        (iface-name iface) (format-ip src-ip) (format-mac src-mac))
                (when header-p
                  (format progress *text-row-fmt* "IP" "MAC" "Vendor"))
                (force-output progress)
                (run-passes (lambda (u32)
                              (pcap-sendpacket
                               send-handle
                               (build-arp-request src-mac src-ip (u32->ip u32))))
                            cap obs segments
                            :per-host-delay-us per-host-delay-us
                            :wait-seconds wait-seconds :retry retry)
                ;; Fingerprinting probes hosts we have already found, so it
                ;; runs last and only over what actually answered.
                (when fingerprint
                  (let ((found (observer-host-list obs)))
                    (format progress "~&Fingerprinting ~D host~:P, ~D probes each...~%"
                            (length found) (length *probes*))
                    (force-output progress)
                    ;; Drop the outstanding send times: a probe reply arriving
                    ;; seconds later would otherwise be matched against the
                    ;; original scan's request and recorded as a huge RTT.
                    (clrhash (observer-send-times obs))
                    (fingerprint-hosts send-handle cap obs iface found))))))
           (when (plusp (capture-dropped cap))
             (format progress "~&Note: dropped ~D queued frame~:P; the network is busier than the queue is deep.~%"
                     (capture-dropped cap)))
           obs)
      (when cap (stop-capture cap))
      (when send-handle (%pcap-close send-handle))
      (%pcap-close capture-handle))))

;;; Watch mode

(defun watch-round-diff (obs previous progress &key (gone-after 3) on-new-host)
  "Report what changed since the last round; return the new snapshot.

Both PREVIOUS and the return value map ip-u32 -> (mac . consecutive-misses). A
host is only called gone after GONE-AFTER silent rounds: one dropped reply is
not a departure, and reporting it as one would make watch mode unreadable."
  (let ((current (make-hash-table)))
    (dolist (host (observer-host-list obs))
      (let* ((key (ip->u32 (host-ip host)))
             (prior (gethash key previous)))
        (setf (gethash key current) (cons (copy-seq (host-mac host)) 0))
        (cond ((null prior)
               (format progress "  + ~A  ~A  ~A~%"
                       (format-ip (host-ip host)) (format-mac (host-mac host))
                       (or (host-vendor host) ""))
               ;; A rotating address is new every time it rotates, so hooking on
               ;; it would mean an alert per phone per round.
               (when (and on-new-host (not (eq (host-kind host) :randomized)))
                 (host-hook on-new-host host "new")))
              ((not (equalp (car prior) (host-mac host)))
               ;; The one to actually care about: a live address changing hands.
               ;; Hooked whatever the new MAC looks like -- a takeover is a
               ;; takeover even if the address that did it is randomized.
               (format progress "  ! ~A  ~A -> ~A~%"
                       (format-ip (host-ip host))
                       (format-mac (car prior)) (format-mac (host-mac host)))
               (when on-new-host (host-hook on-new-host host "changed"))))))
    (maphash (lambda (key prior)
               (unless (gethash key current)
                 (let ((missed (1+ (cdr prior))))
                   (if (< missed gone-after)
                       ;; Inside the grace window: carry it forward, so it is
                       ;; not re-announced as new when it turns up again.
                       (setf (gethash key current) (cons (car prior) missed))
                       (format progress "  - ~A  ~A~%"
                               (format-ip (u32->ip key)) (format-mac (car prior)))))))
             previous)
    (force-output progress)
    current))

(defun watch-loop (iface progress &key cidr passive per-host-delay-us wait-seconds
                                       retry interval padding baseline
                                       on-new-host on-anomaly)
  "Rescan on an interval, reporting only what changed between rounds.

Each round gets its own observer; continuity lives in the snapshot threaded
through WATCH-ROUND-DIFF, which is also what suppresses flapping."
  (format progress "Watching ~A every ~D second~:P. Ctrl-C to stop.~%"
          (iface-name iface) interval)
  (force-output progress)
  ;; Read the baseline once: re-reading each round would let a file edited
  ;; mid-run silently change what counts as known.
  (let ((previous (make-hash-table))
        (known (when baseline (read-baseline baseline))))
    (loop for round from 1
          do (let ((obs (make-observer
                         ;; Anomalies fire their hook as they are raised, which
                         ;; is the whole point -- a poisoning attempt should not
                         ;; wait for the round to finish.
                         :on-anomaly (when on-anomaly
                                       (lambda (a) (anomaly-hook on-anomaly a))))))
               (scan-once :iface iface :obs obs :cidr cidr :passive passive
                          :per-host-delay-us per-host-delay-us
                          :wait-seconds wait-seconds :retry retry
                          :progress progress)
               (format progress "~&[round ~D] ~D host~:P~%" round
                       (hash-table-count (observer-hosts obs)))
               (setf previous (watch-round-diff obs previous progress
                                                :on-new-host on-new-host))
               (dolist (a (reverse (observer-anomalies obs)))
                 (print-anomaly-text a :stream progress))
               ;; Only unknowns are worth repeating every round; the full
               ;; baseline summary would drown the change log.
               (when known
                 (dolist (host (unknown-hosts known (observer-host-list obs)))
                   (format progress "  ?? unknown device ~A  ~A  ~A~%"
                           (format-ip (host-ip host)) (format-mac (host-mac host))
                           (host-vendor-text host))))
               (when padding
                 (dolist (host (observer-host-list obs))
                   (when (eq (host-padding-kind host) :leak)
                     (format progress "  ~A padding: ~A~%"
                             (format-ip (host-ip host))
                             (hex-string (host-padding host)))))))
             (sleep interval))))

(defun scan-hosts (&key interface cidr (per-host-delay-us 1000) (wait-seconds 2)
                        (retry 2) passive fingerprint)
  "Scan and RETURN the HOST records, sorted by IP.  Prints nothing.

SCAN is the command's entry point: it formats, streams, compares against a
baseline and can exit the process.  This is the library half -- everything the
scan learned, handed back for a caller that wants to do its own thing with it.
SCAN keeps only (ip . mac), which throws away the vendor, the round-trip time,
the fingerprint and the timestamps that were all collected anyway.

The observer is made with no callbacks, so nothing streams; PROGRESS goes to a
broadcast stream with no components, which is the portable bit bucket."
  (let ((iface (if interface (find-iface interface) (default-iface)))
        (obs (make-observer)))
    (scan-once :iface iface :obs obs :cidr cidr :passive passive
               :per-host-delay-us per-host-delay-us
               :wait-seconds wait-seconds :retry retry
               :fingerprint fingerprint
               :progress (make-broadcast-stream)
               :header-p nil)
    (observer-host-list obs)))

(defun scan (&key interface cidr (per-host-delay-us 1000) (wait-seconds 2)
                  (retry 2) passive watch (format :text) padding anomalies-only
                  rtt fingerprint baseline ((:write-baseline baseline-out) nil)
                  on-new-host on-anomaly)
  "Scan a subnet for hosts via ARP.

Returns (values alist status), where ALIST is (ip . mac) pairs and STATUS is a
plist of :unknown and :anomalies counts. Deciding what a non-zero count means --
in particular whether to exit non-zero -- belongs to the caller: this is library
code, and a library that can terminate the process is a trap for anyone
embedding it. MAIN owns --fail-on-anomaly.

INTERFACE is a string like \"en0\"; defaults to the first usable interface.
CIDR is a string like \"192.168.1.0/24\"; defaults to the interface's local subnet.
PER-HOST-DELAY-US throttles the burst of outgoing requests.
WAIT-SECONDS is the additional listen window after the last request is sent.
RETRY is how many extra passes to make over addresses that stayed silent.
PASSIVE listens without transmitting anything at all.
WATCH, when non-nil, is the seconds between rounds; runs until interrupted.
FORMAT is one of :text :json :jsonl :csv.
RTT reports per-host round-trip times.
FINGERPRINT probes each host with the malformed-frame matrix.
BASELINE is a known-hosts path to compare against; WRITE-BASELINE one to save to.
ON-NEW-HOST and ON-ANOMALY are commands to run when those turn up."
  (let ((iface (if interface (find-iface interface) (default-iface))))
    (if watch
        ;; Watch mode is inherently a running commentary, so it always reports
        ;; as text; a single JSON document would never be closed off.
        (watch-loop iface *standard-output*
                    :cidr cidr :passive passive
                    :per-host-delay-us per-host-delay-us
                    :wait-seconds wait-seconds :retry retry
                    :interval watch :padding padding :baseline baseline
                    :on-new-host on-new-host :on-anomaly on-anomaly)
        (let ((obs (make-scan-observer format padding anomalies-only
                                       :on-anomaly-hook on-anomaly)))
          (scan-once :iface iface :obs obs :cidr cidr :passive passive
                     :per-host-delay-us per-host-delay-us
                     :wait-seconds wait-seconds :retry retry
                     :fingerprint fingerprint
                     :progress (progress-stream format)
                     ;; No column header when nothing will be streamed under it.
                     :header-p (and (eq format :text) (not anomalies-only)))
          (let ((hosts (emit-results obs format :padding padding :rtt rtt
                                                :anomalies-only anomalies-only))
                (unknown 0))
            (when (and fingerprint (eq format :text))
              (print-fingerprints hosts))
            (when baseline
              (let ((known (read-baseline baseline)))
                (setf unknown (report-baseline known hosts
                                               :stream (progress-stream format)))
                ;; Outside watch mode, "new" can only mean "not in the
                ;; baseline" -- there is no previous round to compare against.
                ;; Randomized MACs are skipped for the same reason they are not
                ;; counted: they rotate by design, so firing on them would mean
                ;; an alert per phone per run, burying the one that matters.
                (when on-new-host
                  (dolist (host (remove :randomized (unknown-hosts known hosts)
                                        :key #'host-kind))
                    (host-hook on-new-host host "unknown")))))
            (when baseline-out
              (format (progress-stream format) "~&Wrote ~D host~:P to ~A~%"
                      (write-baseline baseline-out hosts) baseline-out))
            (values (loop for host in hosts
                          collect (cons (host-ip host) (host-mac host)))
                    (list :unknown unknown
                          :anomalies (length (observer-anomalies obs)))))))))

(defun scan-cidr (cidr &rest args &key interface per-host-delay-us wait-seconds
                                       retry passive watch format padding anomalies-only)
  "Convenience entry: (scan-cidr \"192.168.1.0/24\")."
  (declare (ignore interface per-host-delay-us wait-seconds retry passive watch
                   format padding anomalies-only))
  (apply #'scan :cidr cidr args))
