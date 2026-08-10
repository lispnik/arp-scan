(in-package #:arp-scan)

(version-string:define-version-parameter +version+ :arp-scan)

(defun options ()
  (list
   (clingon:make-option :string  :short-name #\i :long-name "interface" :key :interface
                        :description "Network interface to use (default: first usable)")
   (clingon:make-option :string  :short-name #\r :long-name "range"     :key :cidr
                        :description "Subnet to scan, e.g. 192.168.1.0/24 (default: iface subnet)")
   (clingon:make-option :integer :short-name #\w :long-name "wait"      :key :wait
                        :initial-value 2
                        :description "Listen window in seconds after the last request")
   (clingon:make-option :integer :short-name #\d :long-name "delay"     :key :delay
                        :initial-value 1000
                        :description "Delay between sent requests in microseconds")
   (clingon:make-option :integer :short-name #\t :long-name "retry"     :key :retry
                        :initial-value 2
                        :description "Extra passes over addresses that stayed silent")
   (clingon:make-option :flag    :short-name #\p :long-name "passive"   :key :passive
                        :description "Listen only; send nothing at all")
   (clingon:make-option :integer :short-name #\W :long-name "watch"     :key :watch
                        :description "Rescan every N seconds, reporting only changes")
   (clingon:make-option :string  :short-name #\f :long-name "format"    :key :format
                        :initial-value "text"
                        :description "Output format: text, json, jsonl, csv")
   (clingon:make-option :flag                    :long-name "padding"   :key :padding
                        :description "Show the Ethernet padding each host replies with")
   (clingon:make-option :flag                    :long-name "anomalies-only" :key :anomalies-only
                        :description "Report only conflicting ARP claims, not every host")
   (clingon:make-option :flag                    :long-name "rtt"       :key :rtt
                        :description "Measure and report per-host round-trip time")
   (clingon:make-option :flag                    :long-name "fingerprint" :key :fingerprint
                        :description "Probe each host with malformed ARP frames and group by response pattern")
   (clingon:make-option :string                  :long-name "baseline"  :key :baseline
                        :description "Known-hosts file to compare against; flags unknown devices")
   (clingon:make-option :string                  :long-name "write-baseline" :key :write-baseline
                        :description "Save the hosts found to a known-hosts file")
   (clingon:make-option :flag                    :long-name "fail-on-anomaly" :key :fail-on-anomaly
                        :description "Exit 2 if anomalies or unknown hosts are found (for cron)")
   (clingon:make-option :string                  :long-name "on-new-host" :key :on-new-host
                        :description "Run this command for each new or unknown host")
   (clingon:make-option :string                  :long-name "on-anomaly" :key :on-anomaly
                        :description "Run this command for each anomaly raised")
   (clingon:make-option :string                  :long-name "targets"   :key :targets
                        :description "File of targets, one per line, # for comments")
   (clingon:make-option :string                  :long-name "wake"      :key :wake
                        :description "Send a Wake-on-LAN magic packet to a MAC and exit")
   (clingon:make-option :flag    :short-name #\l :long-name "list"      :key :list
                        :description "List interfaces and exit")))

(defun read-target-file (path)
  "Read a target file into a comma-separated spec.

Same shape as the baseline file: one entry per line, # starts a comment. That
keeps a target list something you can maintain in an editor and diff."
  (unless (probe-file path)
    (error 'usage-error :message (format nil "No such target file: ~A" path)))
  (let ((specs '()))
    (with-open-file (in path :external-format :utf-8)
      (loop for line = (read-line in nil nil)
            while line
            do (let* ((hash (position #\# line))
                      (body (string-trim '(#\Space #\Tab #\Return)
                                         (subseq line 0 hash))))
                 (unless (zerop (length body))
                   (push body specs)))))
    (unless specs
      (error 'usage-error :message (format nil "No targets in ~A" path)))
    (format nil "~{~A~^,~}" (nreverse specs))))

(defun wake (mac-string interface)
  "Send a Wake-on-LAN magic packet to MAC-STRING."
  (let ((mac (or (parse-mac mac-string)
                 (error 'usage-error :message
                        (format nil "Not a MAC address: ~S" mac-string))))
        (iface (if interface (find-iface interface) (default-iface))))
    (let ((handle (pcap-open-live (iface-name iface)
                                  :snaplen 96 :promisc nil :timeout-ms 50)))
      (unwind-protect
           (progn
             (pcap-sendpacket handle (build-wol-packet (iface-mac iface) mac))
             (format t "~&Magic packet sent to ~A on ~A~%"
                     (format-mac mac) (iface-name iface)))
        (%pcap-close handle)))))

(define-condition usage-error (error)
  ((message :initarg :message :reader usage-error-message))
  (:report (lambda (c s) (write-string (usage-error-message c) s))))

(defun check-option-combination (cmd)
  "Reject requests that cannot be honored as written.

Both of these used to be accepted and then quietly ignored, which is the worst
of the options available: the user gets output that looks like an answer to the
question they asked."
  (let ((format (parse-format (clingon:getopt cmd :format))))
    (when (and (clingon:getopt cmd :passive) (clingon:getopt cmd :fingerprint))
      (error 'usage-error :message
             "--fingerprint has to transmit probes, which --passive forbids. Pick one."))
    (when (and (clingon:getopt cmd :watch) (structured-format-p format))
      (error 'usage-error :message
             (format nil "--watch reports changes as they happen and cannot emit ~(~A~): a single document would never be closed off. Use --format text, or drop --watch."
                     format)))
    (when (and (clingon:getopt cmd :on-new-host)
               (not (or (clingon:getopt cmd :watch) (clingon:getopt cmd :baseline))))
      ;; Without one of those there is nothing for "new" to be new against, and
      ;; the hook would fire once per host on the network.
      (error 'usage-error :message
             "--on-new-host needs --watch or --baseline to say what counts as new."))
    (when (and (clingon:getopt cmd :targets) (clingon:getopt cmd :cidr))
      (error 'usage-error :message "Use --targets or --range, not both."))
    format))

(defun dispatch (cmd)
  (cond
    ((clingon:getopt cmd :list)
     (list-interfaces))
    ((clingon:getopt cmd :wake)
     (wake (clingon:getopt cmd :wake) (clingon:getopt cmd :interface)))
    (t
     (let ((format (check-option-combination cmd)))
       (multiple-value-bind (hosts status)
           (scan :interface         (clingon:getopt cmd :interface)
                 :cidr              (or (clingon:getopt cmd :cidr)
                                        (let ((f (clingon:getopt cmd :targets)))
                                          (when f (read-target-file f))))
                 :wait-seconds      (clingon:getopt cmd :wait)
                 :per-host-delay-us (clingon:getopt cmd :delay)
                 :retry             (clingon:getopt cmd :retry)
                 :passive           (clingon:getopt cmd :passive)
                 :watch             (clingon:getopt cmd :watch)
                 :format            format
                 :padding           (clingon:getopt cmd :padding)
                 :anomalies-only    (clingon:getopt cmd :anomalies-only)
                 :rtt               (clingon:getopt cmd :rtt)
                 :fingerprint       (clingon:getopt cmd :fingerprint)
                 :baseline          (clingon:getopt cmd :baseline)
                 :write-baseline    (clingon:getopt cmd :write-baseline)
                 :on-new-host       (clingon:getopt cmd :on-new-host)
                 :on-anomaly        (clingon:getopt cmd :on-anomaly))
         (declare (ignore hosts))
         ;; The exit decision lives here, not in SCAN: turning a result into a
         ;; process status is the command's job.
         (when (clingon:getopt cmd :fail-on-anomaly)
           (let ((unknown (getf status :unknown 0))
                 (anomalies (getf status :anomalies 0)))
             (when (or (plusp unknown) (plusp anomalies))
               (format *error-output* "~&~D unknown host~:P, ~D anomal~:@P~%"
                       unknown anomalies)
               (uiop:quit 2)))))))))

(defun handler (cmd)
  "Run the command, reporting failures in terms the user can act on.

The handling has to happen *here* rather than in MAIN. CLINGON:RUN wraps this
call in its own HANDLER-CASE ending in a catch-all `error' clause, so anything
signalled from here is caught, printed bare, and turned into an exit before it
could ever reach a handler wrapped around CLINGON:RUN itself. The needs-root
hint below sat unreachable for exactly that reason."
  (handler-case (dispatch cmd)
    ;; Bad input is a typo, not a malfunction. 64 is EX_USAGE, matching what
    ;; clingon returns for its own argument errors.
    ((or usage-error invalid-target unusable-interface) (e)
      (format *error-output* "~&~A~%See 'arp-scan --help'.~%" e)
      (uiop:quit 64))
    (pcap-error (e)
      (format *error-output* "~&~A~%~
                              Hint: raw packet send/receive needs root. Try: sudo arp-scan~%" e)
      (uiop:quit 1))))

(defun make-app ()
  (clingon:make-command
   :name        "arp-scan"
   :version     +version+
   :description "ARP scanner for discovering hosts on a local Ethernet."
   :license     "MIT"
   :usage       "[OPTIONS]"
   :options     (options)
   :handler     #'handler
   :examples    '(("Scan the local subnet:" . "sudo arp-scan")
                  ("Scan a specific subnet on en0:" . "sudo arp-scan -i en0 -r 192.168.1.0/24")
                  ("Watch for devices joining and leaving:" . "sudo arp-scan --watch 30")
                  ("Listen without transmitting anything:" . "sudo arp-scan --passive -w 60")
                  ("Report only conflicting ARP claims:" . "sudo arp-scan --anomalies-only")
                  ("Machine-readable output:" . "sudo arp-scan --format json")
                  ("Record the current network as approved:" . "sudo arp-scan --write-baseline known.txt")
                  ("Alert on anything not in the baseline:" . "sudo arp-scan --baseline known.txt --fail-on-anomaly")
                  ("Group hosts by ARP stack behavior:" . "sudo arp-scan --fingerprint")
                  ("List interfaces (no root needed):" . "arp-scan -l"))))

(defun main ()
  ;; Ctrl-C is the ordinary way to leave watch mode; clingon catches SIGINT
  ;; itself and exits 130, so there is nothing to add here.
  ;;
  ;; This is only a backstop for what happens outside CLINGON:RUN's own
  ;; handling -- building the command, say. Everything raised while the command
  ;; runs is dealt with in HANDLER, which sits inside clingon's handler-case.
  (handler-case (clingon:run (make-app))
    (error (e)
      (format *error-output* "Error: ~A~%" e)
      (uiop:quit 1))))
