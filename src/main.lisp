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
   (clingon:make-option :flag    :short-name #\l :long-name "list"      :key :list
                        :description "List interfaces and exit")))

(defun handler (cmd)
  (cond
    ((clingon:getopt cmd :list)
     (list-interfaces))
    (t
     (scan :interface         (clingon:getopt cmd :interface)
           :cidr              (clingon:getopt cmd :cidr)
           :wait-seconds      (clingon:getopt cmd :wait)
           :per-host-delay-us (clingon:getopt cmd :delay)
           :retry             (clingon:getopt cmd :retry)
           :passive           (clingon:getopt cmd :passive)
           :watch             (clingon:getopt cmd :watch)
           :format            (parse-format (clingon:getopt cmd :format))
           :padding           (clingon:getopt cmd :padding)
           :anomalies-only    (clingon:getopt cmd :anomalies-only)
           :rtt               (clingon:getopt cmd :rtt)
           :fingerprint       (clingon:getopt cmd :fingerprint)
           :baseline          (clingon:getopt cmd :baseline)
           :write-baseline    (clingon:getopt cmd :write-baseline)
           :fail-on-anomaly   (clingon:getopt cmd :fail-on-anomaly)))))

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
  (handler-case (clingon:run (make-app))
    (pcap-error (e)
      (format *error-output* "~A~%~
                              Hint: raw packet send/receive needs root. Try: sudo arp-scan~%" e)
      (uiop:quit 1))
    (error (e)
      (format *error-output* "Error: ~A~%" e)
      (uiop:quit 1))))
