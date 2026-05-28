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
           :per-host-delay-us (clingon:getopt cmd :delay)))))

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
                  ("List interfaces (no root needed):" . "arp-scan -l"))))

(defun main ()
  (handler-case (clingon:run (make-app))
    (pcap-error (e)
      (format *error-output* "~A~%~
                              Hint: raw packet send/receive needs root. Try: sudo arp-scan~%" e)
      (uiop:quit 1))
    (error (e)
      (format *error-output* "Error: ~A~%" e)
      (uiop:quit 1))))
