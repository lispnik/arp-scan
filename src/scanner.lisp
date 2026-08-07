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
Lisp."
  (format nil "arp and not ether src ~A" (format-mac src-mac)))

(defun open-capture (iface)
  "Open the listening handle, filtered and ready for the capture thread."
  (let ((handle (pcap-open-live (iface-name iface)
                                ;; 96 covers the 60-byte frame plus slack, which
                                ;; is what lets us keep the trailing padding.
                                :snaplen 96 :promisc nil :timeout-ms 50)))
    (handler-case
        (progn (pcap-setfilter handle (capture-filter (iface-mac iface)))
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

(defun send-pass (handle cap obs src-mac src-ip first last per-host-delay-us
                  &key skip-answered)
  "Send an ARP request across the range FIRST..LAST, draining as we go.
Returns how many were sent. With SKIP-ANSWERED, addresses that already replied
are passed over, which is what makes each retry cheaper than the last.

The range is walked rather than listed. Materializing it cost one cons per
address before a single packet went out -- fine for a /24, 16 million for a /8,
and the mechanism by which a bad prefix used to exhaust the heap.

The send stamp is taken immediately after the frame is handed to libpcap, on the
same monotonic clock the capture thread stamps arrivals with, so the difference
is a real round trip rather than a comparison across two clock domains."
  (let ((sent 0))
    (loop for u32 from first to last
          unless (and skip-answered (observer-seen-p obs u32))
            do (pcap-sendpacket handle (build-arp-request src-mac src-ip (u32->ip u32)))
               (note-send obs u32 (capture-now))
               (observe-frames obs (capture-drain cap))
               (incf sent)
               (when (plusp per-host-delay-us)
                 (sleep (/ per-host-delay-us 1.0d6))))
    sent))

(defun make-scan-observer (format padding anomalies-only)
  "An observer wired for streaming output under text format; silent otherwise,
since json and csv cannot be emitted until the run is complete."
  (make-observer
   :on-host (when (and (eq format :text) (not anomalies-only))
              (lambda (host) (print-host-text host :padding padding)))
   :on-anomaly (when (eq format :text)
                 (lambda (a) (print-anomaly-text a)))))

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
              (multiple-value-bind (first last)
                  (if cidr (cidr-range cidr) (subnet-range-from-iface iface))
                ;; Report only what was asked for. Ambient ARP chatter from
                ;; outside the range is still captured -- it just is not ours
                ;; to report here. Use --passive for that.
                (setf (observer-scope obs) (cons first last))
                (format progress "Scanning ~A - ~A on ~A (~A, ~A)~%"
                        (format-ip (u32->ip first)) (format-ip (u32->ip last))
                        (iface-name iface) (format-ip src-ip) (format-mac src-mac))
                (when header-p
                  (format progress *text-row-fmt* "IP" "MAC" "Vendor"))
                (force-output progress)
                (send-pass send-handle cap obs src-mac src-ip first last
                           per-host-delay-us)
                (pump cap obs wait-seconds)
                ;; Retries cover only the silent addresses, so each pass is
                ;; cheaper than the one before it. Stop early once a pass has
                ;; nothing left to ask.
                (loop repeat retry
                      while (plusp (send-pass send-handle cap obs src-mac src-ip
                                              first last per-host-delay-us
                                              :skip-answered t))
                      do (pump cap obs wait-seconds))
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

(defun watch-round-diff (obs previous progress &key (gone-after 3))
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
                       (or (host-vendor host) "")))
              ((not (equalp (car prior) (host-mac host)))
               ;; The one to actually care about: a live address changing hands.
               (format progress "  ! ~A  ~A -> ~A~%"
                       (format-ip (host-ip host))
                       (format-mac (car prior)) (format-mac (host-mac host)))))))
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
                                       retry interval padding baseline)
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
          do (let ((obs (make-observer)))
               (scan-once :iface iface :obs obs :cidr cidr :passive passive
                          :per-host-delay-us per-host-delay-us
                          :wait-seconds wait-seconds :retry retry
                          :progress progress)
               (format progress "~&[round ~D] ~D host~:P~%" round
                       (hash-table-count (observer-hosts obs)))
               (setf previous (watch-round-diff obs previous progress))
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
                  rtt fingerprint baseline ((:write-baseline baseline-out) nil))
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
FAIL-ON-ANOMALY exits non-zero when anomalies or unknown hosts turn up."
  (let ((iface (if interface (find-iface interface) (default-iface))))
    (if watch
        ;; Watch mode is inherently a running commentary, so it always reports
        ;; as text; a single JSON document would never be closed off.
        (watch-loop iface *standard-output*
                    :cidr cidr :passive passive
                    :per-host-delay-us per-host-delay-us
                    :wait-seconds wait-seconds :retry retry
                    :interval watch :padding padding :baseline baseline)
        (let ((obs (make-scan-observer format padding anomalies-only)))
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
              (setf unknown (report-baseline (read-baseline baseline) hosts
                                             :stream (progress-stream format))))
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
