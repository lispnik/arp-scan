;;; Driver for everything except actually sending/receiving packets

(in-package #:arp-scan.smoke)

(defun report (label result-or-error)
  (etypecase result-or-error
    (string    (format t "  ok    ~A -> ~A~%" label result-or-error))
    ((eql t)   (format t "  ok    ~A~%" label))
    (condition (format t "  FAIL  ~A: ~A~%" label result-or-error))))

(defmacro check (label &body body)
  `(handler-case (progn (report ,label (progn ,@body)) t)
     (error (e)   (report ,label e)                    nil)))

(defun hex-bytes (vec)
  (with-output-to-string (s)
    (loop for b across vec
          for first = t then nil
          do (unless first (write-char #\Space s))
             (format s "~2,'0X" b))))

(defun u16-be (vec offset)
  (logior (ash (aref vec offset) 8) (aref vec (1+ offset))))

(defun mac-for (u32)
  "A distinct MAC per address, so synthetic hosts do not look like one MAC
claiming many IPs.

Built on a real OUI (DC:A6:32, Raspberry Pi) rather than an arbitrary prefix:
it keeps the vendor lookup exercised, and it is globally administered, so these
hosts do not all come back as randomized."
  (make-array 6 :element-type '(unsigned-byte 8)
                :initial-contents (list #xdc #xa6 #x32
                                        (ldb (byte 8 16) u32)
                                        (ldb (byte 8 8) u32)
                                        (ldb (byte 8 0) u32))))

(defun make-fake-net (cap &key responds-p (sent (list 0)))
  "A SEND-FN for RUN-PASSES that answers on behalf of a simulated network.

RESPONDS-P is called with the target and the 1-based pass number for that
target; a true return queues a reply, as though the host had answered. Counts
every send into SENT so tests can assert that retries narrow."
  (let ((attempts (make-hash-table)))
    (lambda (u32)
      (incf (first sent))
      (let ((n (incf (gethash u32 attempts 0))))
        (when (funcall responds-p u32 n)
          (arp-scan::capture-push
           cap
           (make-arp-frame :op 2 :spa (arp-scan::u32->ip u32) :sha (mac-for u32))
           (arp-scan::capture-now)))))))

(defun make-arp-frame (&key (op 2) (sha #(#x02 0 0 0 0 #x11)) (spa #(10 0 0 1))
                            (tha #(0 0 0 0 0 0)) (tpa #(10 0 0 99))
                            (pad 0) (length 60))
  "Synthesize an Ethernet+ARP frame so the parser and observer can be driven
without a live capture. PAD fills everything not explicitly set, which is what
leaves bytes 42.. as the Ethernet padding under test."
  (let ((f (make-array length :element-type '(unsigned-byte 8) :initial-element pad)))
    (replace f #(#xff #xff #xff #xff #xff #xff) :start1 0)
    (replace f sha :start1 6)
    (setf (aref f 12) #x08 (aref f 13) #x06)    ; ethertype ARP
    (setf (aref f 14) 0    (aref f 15) 1)       ; htype Ethernet
    (setf (aref f 16) #x08 (aref f 17) #x00)    ; ptype IPv4
    (setf (aref f 18) 6    (aref f 19) 4)       ; hlen / plen
    (setf (aref f 20) 0    (aref f 21) op)
    (replace f sha :start1 22)
    (replace f spa :start1 28)
    (replace f tha :start1 32)
    (replace f tpa :start1 38)
    f))

(defun main ()
  (let ((all-ok t))
    (macrolet ((require! (label &body body)
                 `(unless (check ,label ,@body) (setf all-ok nil))))

      (format t "arp-scan smoke test~%~%")

      (format t "[1] libpcap CFFI bindings~%")
      (require! "libpcap loadable"
        (unless (cffi:foreign-library-loaded-p 'arp-scan::libpcap)
          (error "library not loaded"))
        t)

      (format t "~%[2] Interface enumeration~%")
      (let ((ifaces nil) (default nil))
        (require! "get-ifaces returns a non-empty list"
          (setf ifaces (arp-scan::get-ifaces))
          (unless (consp ifaces) (error "no interfaces returned"))
          (format nil "~D interfaces" (length ifaces)))
        (require! "at least one iface has IPv4 + MAC + netmask"
          (unless (find-if #'arp-scan::usable-iface-p ifaces)
            (error "none of ~D interfaces is usable" (length ifaces)))
          t)
        (require! "default-iface picks something usable"
          (setf default (arp-scan::default-iface))
          (format nil "~A  ip=~A  mac=~A"
                  (arp-scan::iface-name default)
                  (arp-scan::format-ip (arp-scan::iface-ip default))
                  (arp-scan::format-mac (arp-scan::iface-mac default))))
        (when default
          (require! "default-iface is not link-local"
            (when (arp-scan::link-local-p (arp-scan::iface-ip default))
              (error "picked a 169.254.x.x address"))
            t)))

      (format t "~%[2b] Interface selection~%")
      ;; Hermetic, unlike [2]: every interface here is a synthetic struct, so
      ;; each branch of IFACE-UNUSABLE-REASON runs on every host, not just on
      ;; one that happens to have a tunnel or an unplugged port.
      (flet ((mk (name &key (up t) (running up) loopback ip netmask mac)
               (arp-scan::make-iface
                :name name
                :flags (logior (if up arp-scan::+iff-up+ 0)
                               (if running arp-scan::+iff-running+ 0)
                               (if loopback arp-scan::+iff-loopback+ 0))
                :ip ip :netmask netmask :mac mac))
             (reason (iface &rest args)
               (apply #'arp-scan::iface-unusable-reason iface args)))
        (let* ((ip (arp-scan::parse-ip "10.0.0.5"))
               (mask (arp-scan::parse-ip "255.255.255.0"))
               (mac (make-array 6 :element-type '(unsigned-byte 8)
                                  :initial-contents '(2 0 0 0 0 1)))
               (good (mk "eth0" :ip ip :netmask mask :mac mac))
               (lo (mk "lo0" :loopback t :ip (arp-scan::parse-ip "127.0.0.1")
                             :netmask (arp-scan::parse-ip "255.0.0.0")))
               (tunnel (mk "utun3" :ip ip :netmask mask))
               (down (mk "eth1" :up nil :ip ip :netmask mask :mac mac))
               ;; The unplugged case: administratively up, no link, no address.
               (unplugged (mk "eth3" :up t :running nil :mac mac))
               (noip (mk "eth2" :mac mac))
               (nomask (mk "tap0" :ip ip :mac mac))
               (ifaces (list good lo tunnel down unplugged noip nomask)))
          (require! "a complete, up interface is usable"
            (let ((r (reason good))) (when r (error "refused: ~A" r)))
            t)
          (require! "the loopback interface is refused"
            (let ((r (reason lo)))
              (unless (and r (search "loopback" r)) (error "wrong reason: ~A" r))
              r))
          (require! "an interface with no hardware address is refused, not crashed on"
            ;; This is what -i utun23 hit: a point-to-point tunnel has an IPv4
            ;; address but no MAC, and the old code got as far as FORMAT-MAC on NIL.
            (let ((r (reason tunnel)))
              (unless (and r (search "hardware address" r)) (error "wrong reason: ~A" r))
              "refused"))
          (require! "a down interface is refused"
            (let ((r (reason down)))
              (unless (equal r "it is down") (error "wrong reason: ~A" r))
              r))
          (require! "an unplugged port is reported as no carrier, not as missing an address"
            (let ((r (reason unplugged)))
              (unless (and r (search "no carrier" r)) (error "wrong reason: ~A" r))
              r))
          (require! "an interface with no IPv4 address is refused for a scan"
            (let ((r (reason noip)))
              (unless (equal r "it has no IPv4 address") (error "wrong reason: ~A" r))
              r))
          (require! "the netmask is demanded only when the range comes from the interface"
            (unless (equal (reason nomask) "it has no IPv4 netmask")
              (error "no netmask accepted: ~A" (reason nomask)))
            (let ((r (reason nomask :needs '(:ip))))
              (when r (error "refused with an explicit range: ~A" r)))
            "needed without -r, not with")
          (require! "--wake needs only a MAC and a live link"
            (let ((r (reason noip :needs '())))
              (when r (error "an IPv4-less port was refused: ~A" r)))
            (unless (reason tunnel :needs '())
              (error "relaxing :needs waived the hardware-address check"))
            (unless (and (reason down :needs '()) (reason unplugged :needs '()))
              (error "relaxing :needs waived the link check"))
            t)
          (require! "usable-iface-p agrees with iface-unusable-reason"
            (unless (arp-scan::usable-iface-p good) (error "good refused"))
            (let ((wrong (remove-if-not #'arp-scan::usable-iface-p (rest ifaces))))
              (when wrong (error "accepted ~{~A~^, ~}" (mapcar #'arp-scan::iface-name wrong))))
            t)
          (require! "find-iface returns the usable interface"
            (unless (eq good (arp-scan::find-iface "eth0" :ifaces ifaces))
              (error "did not return eth0"))
            "eth0")
          (require! "find-iface signals with the same reason"
            (handler-case
                (progn (arp-scan::find-iface "utun3" :ifaces ifaces)
                       (error "accepted utun3"))
              (arp-scan::unusable-interface (e)
                (unless (equal (arp-scan::unusable-interface-reason e) (reason tunnel))
                  (error "reasons differ"))
                (arp-scan::unusable-interface-name e))))
          (require! "a nonexistent interface is refused by name"
            (handler-case (progn (arp-scan::find-iface "definitely-not-an-iface0" :ifaces ifaces)
                                 (error "accepted a name that does not exist"))
              (arp-scan::unusable-interface (e) (arp-scan::unusable-interface-reason e))))
          (require! "unusable-interface is part of the library API"
            ;; A caller of SCAN-HOSTS handles it by name, through the package,
            ;; not via arp-scan:: -- so the symbol and its readers are exported.
            (dolist (sym '("UNUSABLE-INTERFACE" "UNUSABLE-INTERFACE-NAME"
                           "UNUSABLE-INTERFACE-REASON"))
              (multiple-value-bind (s status) (find-symbol sym :arp-scan)
                (unless (and s (eq status :external))
                  (error "~A is ~A" sym (or status "missing")))))
            t)
          (require! "iface-needs drops the netmask only for an explicit range"
            (unless (and (equal (arp-scan::iface-needs "10.0.0.0/24") '(:ip))
                         (equal (arp-scan::iface-needs nil) '(:ip :netmask)))
              (error "wrong needs"))
            t)
          (require! "a non-Ethernet link type is refused; Ethernet is not"
            (when (arp-scan::datalink-unusable-reason arp-scan::+dlt-en10mb+)
              (error "refused DLT_EN10MB"))
            (let ((r (arp-scan::datalink-unusable-reason 12)))
              (unless (and r (search "link type 12" r)) (error "accepted DLT 12: ~A" r))
              r))))

      (format t "~%[3] CIDR / subnet math~%")
      (require! "10.0.0.0/30 excludes network + broadcast"
        (multiple-value-bind (a b) (arp-scan::cidr-range "10.0.0.0/30")
          (unless (and (= a (arp-scan::ip->u32 (arp-scan::parse-ip "10.0.0.1")))
                       (= b (arp-scan::ip->u32 (arp-scan::parse-ip "10.0.0.2"))))
            (error "got ~A - ~A"
                   (arp-scan::format-ip (arp-scan::u32->ip a))
                   (arp-scan::format-ip (arp-scan::u32->ip b)))))
        "10.0.0.1 - 10.0.0.2")
      (require! "10.0.0.5/32 is a single host"
        (multiple-value-bind (a b) (arp-scan::cidr-range "10.0.0.5/32")
          (unless (= a b) (error "got range ~A - ~A" a b)))
        "10.0.0.5")
      (require! "192.168.1.0/24 has 254 host range"
        (multiple-value-bind (a b) (arp-scan::cidr-range "192.168.1.0/24")
          (unless (= (1+ (- b a)) 254) (error "got ~D hosts" (1+ (- b a)))))
        "254 hosts")
      (require! "an out-of-range prefix is rejected, not silently widened"
        ;; /99 used to make the mask zero, yielding all of IPv4 -- which the
        ;; scanner then tried to walk, exhausting the heap.
        (dolist (bad '("192.168.1.0/99" "192.168.1.0/33"))
          (handler-case (progn (arp-scan::cidr-range bad)
                               (error "accepted ~A" bad))
            (arp-scan::invalid-target () t)))
        "/33 and /99 refused")
      (require! "malformed ranges are rejected with a usable message"
        (dolist (bad '("192.168.1.0" "999.1.1.0/24" "192.168.1/24"
                       "192.168.1.0/abc" "192.168.1.0/" "1.2.3.4.5/24" ""))
          (handler-case (progn (arp-scan::cidr-range bad)
                               (error "accepted ~S" bad))
            (arp-scan::invalid-target () t)))
        "7 rejected")
      (require! "/0 is still legal, minus network and broadcast"
        (multiple-value-bind (a b) (arp-scan::cidr-range "0.0.0.0/0")
          (unless (and (= a 1) (= b (- (expt 2 32) 2)))
            (error "got ~A - ~A" a b)))
        "0.0.0.1 - 255.255.255.254")
      (require! "valid dotted quads still parse, edges included"
        (unless (equalp (arp-scan::parse-ip "0.0.0.0") #(0 0 0 0)) (error "0.0.0.0"))
        (unless (equalp (arp-scan::parse-ip "255.255.255.255") #(255 255 255 255))
          (error "255.255.255.255"))
        "0.0.0.0 and 255.255.255.255")

      (format t "~%[4] OUI vendor lookup~%")
      (require! "OUI table is populated"
        (let ((n (hash-table-count arp-scan::*oui-table*)))
          (when (< n 1000) (error "only ~D entries loaded" n))
          (format nil "~D entries" n)))
      (require! "DC:A6:32 -> Raspberry Pi"
        (let ((v (arp-scan::oui-lookup #(#xdc #xa6 #x32 0 0 0))))
          (unless (and v (search "Raspberry" v))
            (error "got ~S" v))
          v))
      (require! "FF:FF:FF -> nil (unassigned)"
        (let ((v (arp-scan::oui-lookup #(#xff #xff #xff 0 0 0))))
          (when v (error "got ~S" v))
          "nil"))

      (format t "~%[5] ARP frame layout~%")
      (let* ((src-mac #(#x0a #xb9 #x7e #xa0 #x51 #x7d))
             (src-ip  #(192 168 50 149))
             (tgt-ip  #(192 168 50 1))
             (frame   (arp-scan::build-arp-request src-mac src-ip tgt-ip)))
        (require! "frame is 60 bytes"
          (unless (= (length frame) 60) (error "got ~D" (length frame)))
          "60")
        (require! "dst MAC is broadcast"
          (unless (every (lambda (b) (= b #xff)) (subseq frame 0 6))
            (error "got ~A" (hex-bytes (subseq frame 0 6))))
          "ff:ff:ff:ff:ff:ff")
        (require! "ethertype is 0x0806"
          (let ((et (u16-be frame 12)))
            (unless (= et #x0806) (error "got 0x~4,'0X" et))
            "0x0806"))
        (require! "opcode is ARP request (1)"
          (let ((op (u16-be frame 20)))
            (unless (= op 1) (error "got ~D" op))
            "1"))
        (require! "sender IP at offset 28..32 = src-ip"
          (let ((spa (subseq frame 28 32)))
            (unless (equalp spa src-ip)
              (error "got ~A" (hex-bytes spa)))
            (arp-scan::format-ip spa)))
        (require! "target IP at offset 38..42 = tgt-ip"
          (let ((tpa (subseq frame 38 42)))
            (unless (equalp tpa tgt-ip)
              (error "got ~A" (hex-bytes tpa)))
            (arp-scan::format-ip tpa)))
        (require! "target MAC field is zeroed"
          (unless (every #'zerop (subseq frame 32 38))
            (error "got ~A" (hex-bytes (subseq frame 32 38))))
          "00:00:00:00:00:00"))

      (format t "~%[6] Generalized ARP parsing~%")
      (require! "parse-arp reads a request (opcode 1)"
        (multiple-value-bind (op spa sha)
            (arp-scan::parse-arp (make-arp-frame :op 1 :spa #(192 168 1 7)
                                                 :sha #(#xaa #xbb #xcc 0 0 1)))
          (unless (and op (= op 1)) (error "opcode ~S" op))
          (unless (equalp spa #(192 168 1 7)) (error "spa ~A" (hex-bytes spa)))
          (unless (equalp sha #(#xaa #xbb #xcc 0 0 1)) (error "sha ~A" (hex-bytes sha)))
          (format nil "op=1 ~A" (arp-scan::format-ip spa))))
      (require! "parse-arp-reply still rejects requests"
        (when (arp-scan::parse-arp-reply (make-arp-frame :op 1))
          (error "a request parsed as a reply"))
        "nil")
      (require! "non-ARP frame is rejected"
        (let ((f (make-arp-frame)))
          (setf (aref f 12) #x08 (aref f 13) #x00)   ; IPv4, not ARP
          (when (arp-scan::parse-arp f) (error "parsed a non-ARP frame")))
        "nil")

      (format t "~%[7] Reply padding classification~%")
      (require! "zero-filled padding classifies as :zero"
        (multiple-value-bind (op spa sha tpa tha padding)
            (arp-scan::parse-arp (make-arp-frame :pad 0))
          (declare (ignore op spa sha tpa tha))
          (unless (= (length padding) 18) (error "~D padding bytes" (length padding)))
          (let ((kind (arp-scan::classify-padding padding)))
            (unless (eq kind :zero) (error "got ~S" kind))
            "zero, 18 bytes")))
      (require! "non-zero padding classifies as :leak"
        (multiple-value-bind (op spa sha tpa tha padding)
            (arp-scan::parse-arp (make-arp-frame :pad #xa5))
          (declare (ignore op spa sha tpa tha))
          (let ((kind (arp-scan::classify-padding padding)))
            (unless (eq kind :leak) (error "got ~S" kind))
            (format nil "leak: ~A" (hex-bytes padding)))))
      (require! "a frame with no padding classifies as :none"
        (multiple-value-bind (op spa sha tpa tha padding)
            (arp-scan::parse-arp (make-arp-frame :length 42))
          (declare (ignore op spa sha tpa tha))
          (let ((kind (arp-scan::classify-padding padding)))
            (unless (eq kind :none) (error "got ~S" kind))
            "none")))

      (format t "~%[8] Anomaly detection~%")
      (require! "two MACs claiming one IP raises :ip-conflict"
        (let ((obs (arp-scan::make-observer)))
          (arp-scan::observe-frame obs (make-arp-frame :spa #(10 0 0 5)
                                                       :sha #(#x02 0 0 0 0 #xaa)))
          (arp-scan::observe-frame obs (make-arp-frame :spa #(10 0 0 5)
                                                       :sha #(#x02 0 0 0 0 #xbb)))
          (let ((host (gethash (arp-scan::ip->u32 #(10 0 0 5))
                               (arp-scan::observer-hosts obs))))
            (unless host (error "no host recorded"))
            (unless (= 1 (length (arp-scan::host-alt-macs host)))
              (error "~D alt MACs" (length (arp-scan::host-alt-macs host))))
            (unless (find :ip-conflict (arp-scan::observer-anomalies obs)
                          :key #'arp-scan::anomaly-kind)
              (error "no :ip-conflict raised")))
          ;; One host, not two: a conflicting claim must not create a second entry.
          (unless (= 1 (hash-table-count (arp-scan::observer-hosts obs)))
            (error "~D hosts" (hash-table-count (arp-scan::observer-hosts obs))))
          "1 host, 1 conflict"))
      (require! "a repeated claim from the same MAC is not a conflict"
        (let ((obs (arp-scan::make-observer)))
          (dotimes (i 3)
            (arp-scan::observe-frame obs (make-arp-frame :spa #(10 0 0 6))))
          (when (arp-scan::observer-anomalies obs)
            (error "~D spurious anomalies" (length (arp-scan::observer-anomalies obs))))
          "no anomalies"))
      (require! "sender == target raises :gratuitous"
        (let ((obs (arp-scan::make-observer)))
          (arp-scan::observe-frame obs (make-arp-frame :spa #(10 0 0 7) :tpa #(10 0 0 7)))
          (unless (find :gratuitous (arp-scan::observer-anomalies obs)
                        :key #'arp-scan::anomaly-kind)
            (error "no :gratuitous raised"))
          "gratuitous"))
      (require! "an out-of-scope sender is not reported"
        (let ((obs (arp-scan::make-observer
                    :scope (list (cons (arp-scan::ip->u32 #(10 0 0 1))
                                       (arp-scan::ip->u32 #(10 0 0 9)))))))
          (arp-scan::observe-frame obs (make-arp-frame :spa #(10 0 0 5)))
          (arp-scan::observe-frame obs (make-arp-frame :spa #(192 168 1 1)))
          (unless (= 1 (hash-table-count (arp-scan::observer-hosts obs)))
            (error "~D hosts; -r no longer bounds the results"
                   (hash-table-count (arp-scan::observer-hosts obs))))
          "1 of 2 in scope"))
      (require! "an ARP probe (0.0.0.0) is ignored"
        (let ((obs (arp-scan::make-observer)))
          (arp-scan::observe-frame obs (make-arp-frame :op 1 :spa #(0 0 0 0)))
          (unless (zerop (hash-table-count (arp-scan::observer-hosts obs)))
            (error "recorded a host from a probe"))
          "ignored"))

      (format t "~%[9] Output escaping~%")
      (require! "JSON escapes quotes and backslashes"
        (let ((out (with-output-to-string (s)
                     (arp-scan::json-escape "Acme \"X\" \\ Co." s))))
          (unless (string= out "\"Acme \\\"X\\\" \\\\ Co.\"") (error "got ~A" out))
          out))
      (require! "CSV quotes fields containing a comma or a quote"
        (let ((out (with-output-to-string (s)
                     (arp-scan::csv-escape "Acme, \"X\" Ltd" s))))
          (unless (string= out "\"Acme, \"\"X\"\" Ltd\"") (error "got ~A" out))
          out))
      (require! "CSV leaves a plain field alone"
        (let ((out (with-output-to-string (s)
                     (arp-scan::csv-escape "Raspberry Pi Trading Ltd" s))))
          (unless (string= out "Raspberry Pi Trading Ltd") (error "got ~A" out))
          out))
      (require! "format names parse, and junk is rejected"
        (unless (eq :jsonl (arp-scan::parse-format "jsonl")) (error "jsonl"))
        (unless (eq :csv (arp-scan::parse-format "CSV")) (error "case-insensitive"))
        (handler-case (progn (arp-scan::parse-format "yaml")
                             (error "accepted an unknown format"))
          (simple-error () t))
        "text/json/jsonl/csv")

      (format t "~%[10] Capture queue~%")
      (require! "push then drain hands over every frame"
        (let ((cap (arp-scan::make-capture)))
          (dotimes (i 5) (arp-scan::capture-push cap (make-arp-frame)))
          (let ((frames (arp-scan::capture-drain cap)))
            (unless (= 5 (length frames)) (error "drained ~D" (length frames)))
            (format nil "~D frames" (length frames)))))
      (require! "a second drain is empty, not a repeat"
        (let ((cap (arp-scan::make-capture)))
          (arp-scan::capture-push cap (make-arp-frame))
          (arp-scan::capture-drain cap)
          (let ((frames (arp-scan::capture-drain cap)))
            (unless (zerop (length frames)) (error "drained ~D" (length frames))))
          "0 frames"))
      (require! "the queue is bounded and counts what it drops"
        (let ((cap (arp-scan::make-capture))
              (frame (make-arp-frame)))
          (dotimes (i (+ arp-scan::+capture-queue-limit+ 10))
            (arp-scan::capture-push cap frame))
          (unless (= 10 (arp-scan::capture-dropped cap))
            (error "dropped ~D" (arp-scan::capture-dropped cap)))
          (format nil "~D held, ~D dropped"
                  (length (arp-scan::capture-drain cap))
                  (arp-scan::capture-dropped cap))))
      (require! "queued entries carry an arrival stamp"
        (let ((cap (arp-scan::make-capture)))
          (arp-scan::capture-push cap (make-arp-frame) 12.5d0)
          (let ((entry (aref (arp-scan::capture-drain cap) 0)))
            (unless (= (cdr entry) 12.5d0) (error "stamp ~S" (cdr entry)))
            "12.5")))

      (format t "~%[11] MAC address semantics~%")
      (require! "the local bit marks a randomized address"
        (let ((mac #(#x36 #x03 #x50 #x35 #x39 #xa7)))
          (unless (eq :randomized (arp-scan::mac-kind mac))
            (error "got ~S" (arp-scan::mac-kind mac)))
          ;; No vendor is encoded in a software-chosen address, so claiming one
          ;; would be worse than saying nothing.
          (when (arp-scan::oui-lookup mac)
            (error "invented a vendor for a randomized MAC"))
          "randomized, no vendor"))
      (require! "a burned-in address is :global"
        (let ((kind (arp-scan::mac-kind #(#xdc #xa6 #x32 1 2 3))))
          (unless (eq kind :global) (error "got ~S" kind))
          "global"))
      (require! "the multicast bit is detected"
        (let ((kind (arp-scan::mac-kind #(#x01 #x00 #x5e 1 2 3))))
          (unless (eq kind :multicast) (error "got ~S" kind))
          "multicast"))
      (require! "a multicast source raises an anomaly"
        (let ((obs (arp-scan::make-observer)))
          (arp-scan::observe-frame obs (make-arp-frame :sha #(#x01 #x00 #x5e 1 2 3)))
          (unless (find :multicast-source (arp-scan::observer-anomalies obs)
                        :key #'arp-scan::anomaly-kind)
            (error "no :multicast-source raised"))
          "raised"))

      (format t "~%[12] Extended OUI registries~%")
      (require! "MA-M and MA-S tables are populated"
        (let ((n28 (hash-table-count arp-scan::*oui28-table*))
              (n36 (hash-table-count arp-scan::*oui36-table*)))
          (when (or (< n28 1000) (< n36 1000))
            (error "/28 has ~D, /36 has ~D" n28 n36))
          (format nil "~D /28, ~D /36" n28 n36)))
      (require! "a /36 assignment beats its /24 parent"
        (let ((v (arp-scan::oui-lookup #(#x8c #x1f #x64 #xaf #xa0 #x01))))
          (unless (and v (search "DATA ELECTRONIC" v)) (error "got ~S" v))
          ;; The /24 parent is the useless shared name we are trying to avoid.
          (when (search "IEEE Registration" v)
            (error "fell back to the shared parent block"))
          v))
      (require! "a /28 assignment beats its /24 parent"
        (let ((v (arp-scan::oui-lookup #(#xc8 #x5c #xe2 #x70 #x00 #x01))))
          (unless (and v (search "SYNERGY" v)) (error "got ~S" v))
          v))
      (require! "a plain /24 lookup still works"
        (let ((v (arp-scan::oui-lookup #(#xdc #xa6 #x32 #x11 #x22 #x33))))
          (unless (and v (search "Raspberry" v)) (error "got ~S" v))
          v))

      (format t "~%[13] Round-trip timing~%")
      (require! "a reply after a recorded send yields an RTT"
        (let ((obs (arp-scan::make-observer)))
          (arp-scan::note-send obs (arp-scan::ip->u32 #(10 0 0 1)) 100.0d0)
          (arp-scan::observe-frame obs (make-arp-frame :op 2 :spa #(10 0 0 1))
                                   100.0125d0)
          (let* ((host (gethash (arp-scan::ip->u32 #(10 0 0 1))
                                (arp-scan::observer-hosts obs)))
                 (rtt (arp-scan::host-rtt host)))
            (unless rtt (error "no rtt recorded"))
            (unless (< 0.0124 rtt 0.0126) (error "rtt ~F" rtt))
            (format nil "~,2F ms" (* 1000 rtt)))))
      (require! "a reply with no matching send has no RTT"
        (let ((obs (arp-scan::make-observer)))
          (arp-scan::observe-frame obs (make-arp-frame :op 2 :spa #(10 0 0 2)) 5.0d0)
          (let ((host (gethash (arp-scan::ip->u32 #(10 0 0 2))
                               (arp-scan::observer-hosts obs))))
            (when (arp-scan::host-rtt host) (error "invented an rtt")))
          "nil"))

      (format t "~%[14] Baseline / known hosts~%")
      (require! "MAC strings parse in both separators"
        (let ((a (arp-scan::parse-mac "DC:A6:32:F7:9E:AF"))
              (b (arp-scan::parse-mac "dc-a6-32-f7-9e-af")))
          (unless (equalp a b) (error "~A vs ~A" (hex-bytes a) (hex-bytes b)))
          (unless (equalp a #(#xdc #xa6 #x32 #xf7 #x9e #xaf))
            (error "got ~A" (hex-bytes a)))
          "DC:A6:32:F7:9E:AF"))
      (require! "malformed MAC strings are rejected, not guessed at"
        (dolist (bad '("" "zz:zz:zz:zz:zz:zz" "DC:A6:32" "DC:A6:32:F7:9E:AF:00"))
          (when (arp-scan::parse-mac bad) (error "accepted ~S" bad)))
        "4 rejected")
      (require! "a baseline round-trips through a file"
        (let* ((path (merge-pathnames "arp-scan-smoke-baseline.txt"
                                      (uiop:temporary-directory)))
               (hosts (list (arp-scan::make-host :ip #(10 0 0 1)
                                                 :mac #(#xdc #xa6 #x32 1 2 3)
                                                 :vendor "Raspberry Pi Trading Ltd")
                            (arp-scan::make-host :ip #(10 0 0 2)
                                                 :mac #(#x28 #x02 #x44 4 5 6)
                                                 :vendor "Apple, Inc."))))
          (unwind-protect
               (progn
                 (arp-scan::write-baseline path hosts)
                 (let ((bl (arp-scan::read-baseline path)))
                   (unless (= 2 (hash-table-count (arp-scan::baseline-macs bl)))
                     (error "read back ~D" (hash-table-count (arp-scan::baseline-macs bl))))
                   ;; Both known -> nothing unknown, nothing missing.
                   (when (arp-scan::unknown-hosts bl hosts) (error "false unknown"))
                   (when (arp-scan::missing-hosts bl hosts) (error "false missing"))
                   ;; A new device is unknown; a departed one is missing.
                   (let* ((stranger (arp-scan::make-host :ip #(10 0 0 9)
                                                         :mac #(#xaa #xbb #xcc 7 8 9)))
                          (unknown (arp-scan::unknown-hosts bl (list stranger)))
                          (missing (arp-scan::missing-hosts bl (list stranger))))
                     (unless (= 1 (length unknown)) (error "~D unknown" (length unknown)))
                     (unless (= 2 (length missing)) (error "~D missing" (length missing))))
                   "2 known, 1 unknown, 2 missing"))
            (ignore-errors (delete-file path)))))
      (require! "comments and blank lines are skipped"
        (let ((path (merge-pathnames "arp-scan-smoke-baseline2.txt"
                                     (uiop:temporary-directory))))
          (unwind-protect
               (progn
                 (with-open-file (out path :direction :output :if-exists :supersede)
                   (format out "# a comment~%~%DC:A6:32:F7:9E:AF  10.0.0.1  Pi~%"))
                 (let ((bl (arp-scan::read-baseline path)))
                   (unless (= 1 (hash-table-count (arp-scan::baseline-macs bl)))
                     (error "got ~D entries" (hash-table-count (arp-scan::baseline-macs bl))))
                   "1 entry"))
            (ignore-errors (delete-file path)))))
      (require! "randomized MACs are kept out of a written baseline"
        (let* ((path (merge-pathnames "arp-scan-smoke-baseline3.txt"
                                      (uiop:temporary-directory)))
               (hosts (list (arp-scan::make-host :ip #(10 0 0 1)
                                                 :mac #(#xdc #xa6 #x32 1 2 3)
                                                 :kind :global)
                            (arp-scan::make-host :ip #(10 0 0 2)
                                                 :mac #(#x36 #x03 #x50 4 5 6)
                                                 :kind :randomized))))
          (unwind-protect
               (progn
                 (unless (= 1 (arp-scan::write-baseline path hosts))
                   (error "recorded the randomized MAC"))
                 (let ((bl (arp-scan::read-baseline path)))
                   (unless (= 1 (hash-table-count (arp-scan::baseline-macs bl)))
                     (error "read back ~D" (hash-table-count (arp-scan::baseline-macs bl))))
                   ;; It must not come back as a phantom missing device either.
                   (unless (zerop (length (arp-scan::missing-hosts bl (list (first hosts)))))
                     (error "randomized MAC resurfaced as missing")))
                 "1 of 2 recorded")
            (ignore-errors (delete-file path)))))
      (require! "a missing baseline file is empty, not an error"
        (let ((bl (arp-scan::read-baseline "/nonexistent/arp-scan/baseline.txt")))
          (unless (zerop (hash-table-count (arp-scan::baseline-macs bl)))
            (error "conjured entries from nowhere"))
          "empty"))

      (format t "~%[15] Fingerprint probes~%")
      (require! "the probe matrix is non-empty and uniquely named"
        (let ((names (mapcar #'arp-scan::probe-name arp-scan::*probes*)))
          (unless (> (length names) 4) (error "only ~D probes" (length names)))
          (unless (= (length names) (length (remove-duplicates names :test #'string=)))
            (error "duplicate probe names"))
          (format nil "~D probes" (length names))))
      (require! "the control probe builds a well-formed request"
        (let ((frame (arp-scan::build-arp-probe #(1 2 3 4 5 6) #(10 0 0 1) #(10 0 0 2))))
          (unless (= 60 (length frame)) (error "~D bytes" (length frame)))
          (unless (= #x0806 (u16-be frame 12)) (error "ethertype"))
          (unless (= 1 (u16-be frame 20)) (error "opcode"))
          (unless (equalp (subseq frame 38 42) #(10 0 0 2)) (error "target"))
          "well-formed"))
      (require! "each probe override lands in the frame"
        (let ((bad-hrd (arp-scan::build-arp-probe #(1 2 3 4 5 6) #(10 0 0 1) #(10 0 0 2)
                                                  :htype #xffff))
              (bad-op (arp-scan::build-arp-probe #(1 2 3 4 5 6) #(10 0 0 1) #(10 0 0 2)
                                                 :op 255))
              (zero-spa (arp-scan::build-arp-probe #(1 2 3 4 5 6) #(10 0 0 1) #(10 0 0 2)
                                                   :spa #(0 0 0 0)))
              (near-bcast (arp-scan::build-arp-probe #(1 2 3 4 5 6) #(10 0 0 1) #(10 0 0 2)
                                                     :dst #(#xff #xff #xff #xff #xff #xfe))))
          (unless (= #xffff (u16-be bad-hrd 14)) (error "htype not applied"))
          (unless (= 255 (u16-be bad-op 20)) (error "opcode not applied"))
          (unless (every #'zerop (subseq zero-spa 28 32)) (error "spa not applied"))
          (unless (= #xfe (aref near-bcast 5)) (error "dst not applied"))
          "htype/op/spa/dst"))
      (require! "every probe in the matrix builds without error"
        (let ((built 0))
          (dolist (probe arp-scan::*probes*)
            (let ((frame (arp-scan::probe-frame probe #(1 2 3 4 5 6)
                                                #(10 0 0 1) #(10 0 0 2))))
              (unless (= 60 (length frame))
                (error "~A produced ~D bytes" (arp-scan::probe-name probe) (length frame)))
              (incf built)))
          (format nil "~D built" built)))

      ;; The scan loop itself, driven with a stub in place of libpcap. RUN-PASSES
      ;; holds no handles, and the capture queue takes plain byte vectors, so the
      ;; whole pass/retry cycle runs here with no NIC and no root.
      (format t "~%[16] Scan loop~%")
      (let ((base (arp-scan::ip->u32 #(10 0 0 0))))
        (flet ((run (responds-p &key (retry 2) (first (+ base 1)) (last (+ base 10))
                                     segments)
                 (let* ((cap (arp-scan::make-capture))
                        (obs (arp-scan::make-observer))
                        (sent (list 0))
                        (send-fn (make-fake-net cap :responds-p responds-p :sent sent)))
                   (arp-scan::run-passes send-fn cap obs
                                         (or segments (list (cons first last)))
                                         :per-host-delay-us 0 :wait-seconds 0
                                         :retry retry)
                   (values obs (first sent)))))

          (require! "a fully responsive range is found in one pass"
            (multiple-value-bind (obs sent)
                (run (lambda (u32 n) (declare (ignore u32 n)) t))
              (let ((found (hash-table-count (arp-scan::observer-hosts obs))))
                (unless (= found 10) (error "found ~D of 10" found))
                ;; 10 asked once; the first retry finds nothing to ask and stops.
                (unless (= sent 10) (error "sent ~D, expected 10" sent))
                (format nil "10 hosts, ~D sends" sent))))

          (require! "retries re-ask only the addresses that stayed silent"
            (multiple-value-bind (obs sent)
                ;; Only the first three ever answer.
                (run (lambda (u32 n) (declare (ignore n)) (<= u32 (+ base 3))))
              (let ((found (hash-table-count (arp-scan::observer-hosts obs))))
                (unless (= found 3) (error "found ~D of 3" found))
                ;; 10 in the first pass, then 7 silent ones twice over.
                (unless (= sent (+ 10 7 7)) (error "sent ~D, expected 24" sent))
                (format nil "3 hosts, ~D sends" sent))))

          (require! "a host that only answers on the second try is still found"
            ;; This is the entire reason --retry exists: one dropped reply
            ;; should not read as a dead address.
            (multiple-value-bind (obs sent)
                (run (lambda (u32 n) (declare (ignore u32)) (>= n 2)))
              (let ((found (hash-table-count (arp-scan::observer-hosts obs))))
                (unless (= found 10) (error "found ~D of 10" found))
                (unless (= sent 20) (error "sent ~D, expected 20" sent))
                (format nil "10 hosts after retry, ~D sends" sent))))

          (require! "retry 0 means exactly one pass"
            (multiple-value-bind (obs sent)
                (run (lambda (u32 n) (declare (ignore u32)) (>= n 2)) :retry 0)
              (unless (zerop (hash-table-count (arp-scan::observer-hosts obs)))
                (error "found hosts without a retry"))
              (unless (= sent 10) (error "sent ~D, expected 10" sent))
              "1 pass, 10 sends"))

          (require! "a silent range yields nothing and gives up after its retries"
            (multiple-value-bind (obs sent)
                (run (lambda (u32 n) (declare (ignore u32 n)) nil))
              (unless (zerop (hash-table-count (arp-scan::observer-hosts obs)))
                (error "invented hosts"))
              (unless (= sent 30) (error "sent ~D, expected 30" sent))
              "0 hosts, 3 full passes"))

          (require! "replies carry through to vendor and round-trip time"
            (multiple-value-bind (obs sent)
                (run (lambda (u32 n) (declare (ignore u32 n)) t)
                     :first (+ base 1) :last (+ base 1))
              (declare (ignore sent))
              (let ((host (gethash (+ base 1) (arp-scan::observer-hosts obs))))
                (unless host (error "no host"))
                (unless (arp-scan::host-rtt host) (error "no rtt measured"))
                (unless (eq :global (arp-scan::host-kind host))
                  (error "kind ~S" (arp-scan::host-kind host)))
                (unless (>= (arp-scan::host-rtt host) 0)
                  (error "negative rtt ~F" (arp-scan::host-rtt host)))
                (let ((vendor (arp-scan::host-vendor host)))
                  (unless (and vendor (search "Raspberry" vendor))
                    (error "vendor ~S" vendor))
                  (format nil "~A, rtt ~,3F ms"
                          vendor (* 1000 (arp-scan::host-rtt host)))))))

          (require! "disjoint segments are all covered in one run"
            (multiple-value-bind (obs sent)
                (run (lambda (u32 n) (declare (ignore u32 n)) t)
                     :segments (list (cons (+ base 1) (+ base 3))
                                     (cons (+ base 100) (+ base 102))))
              (let ((found (hash-table-count (arp-scan::observer-hosts obs))))
                (unless (= found 6) (error "found ~D of 6" found))
                (unless (= sent 6) (error "sent ~D of 6" sent))
                "2 segments, 6 hosts")))

          (require! "a wide range is walked, not listed"
            ;; A /16 with nothing answering. The point is that it completes at
            ;; all: this loop used to cons one cell per address up front, which
            ;; is how a mistyped prefix exhausted the heap.
            (let ((wide-first (arp-scan::ip->u32 #(10 1 0 1)))
                  (wide-last (arp-scan::ip->u32 #(10 1 255 254))))
              (multiple-value-bind (obs sent)
                  (run (lambda (u32 n) (declare (ignore u32 n)) nil)
                       :retry 0 :first wide-first :last wide-last)
                (declare (ignore obs))
                (unless (= sent (1+ (- wide-last wide-first)))
                  (error "sent ~D of ~D" sent (1+ (- wide-last wide-first))))
                (format nil "~:D addresses" sent))))))

      (format t "~%[17] VLAN-tagged frames~%")
      (flet ((tagged (&key (tpid arp-scan::+ethertype-vlan+) (vid 100) (tags 1))
               ;; An 802.1Q tag is four bytes between the source MAC and the
               ;; ethertype, so everything after it shifts.
               (let* ((shift (* 4 tags))
                      (f (make-array (+ 64 shift) :element-type '(unsigned-byte 8)
                                                  :initial-element 0)))
                 (dotimes (i tags)
                   (arp-scan::set-u16-be f (+ 12 (* 4 i)) tpid)
                   (arp-scan::set-u16-be f (+ 14 (* 4 i)) vid))
                 (arp-scan::set-u16-be f (+ 12 shift) #x0806)     ; ethertype ARP
                 (arp-scan::set-u16-be f (+ 20 shift) 2)          ; opcode reply
                 (replace f #(#x02 0 0 0 0 #x11) :start1 (+ 22 shift))
                 (replace f #(10 0 0 7) :start1 (+ 28 shift))
                 f)))
        (require! "a tagged ARP reply parses, with its VLAN id"
          (multiple-value-bind (op spa sha tpa tha pad vlan)
              (arp-scan::parse-arp (tagged :vid 100))
            (declare (ignore sha tpa tha pad))
            (unless op (error "not recognized as ARP at all"))
            (unless (= op 2) (error "op ~D" op))
            (unless (equalp spa #(10 0 0 7)) (error "spa ~A" (hex-bytes spa)))
            (unless (eql vlan 100) (error "vlan ~S" vlan))
            (format nil "vlan 100, ~A" (arp-scan::format-ip spa))))
        (require! "the priority bits are not mistaken for the VLAN id"
          ;; The id is the low 12 bits of the TCI; the top 4 are priority and
          ;; the drop-eligible flag.
          (multiple-value-bind (op spa sha tpa tha pad vlan)
              (arp-scan::parse-arp (tagged :vid #xE064))
            (declare (ignore op spa sha tpa tha pad))
            (unless (eql vlan 100) (error "vlan ~S, expected 100" vlan))
            "100"))
        (require! "a QinQ double tag is unwrapped"
          (multiple-value-bind (op spa sha tpa tha pad vlan)
              (arp-scan::parse-arp (tagged :tpid arp-scan::+ethertype-qinq+
                                           :vid 200 :tags 2))
            (declare (ignore sha tpa tha pad))
            (unless op (error "double-tagged frame not recognized"))
            (unless (equalp spa #(10 0 0 7)) (error "spa ~A" (hex-bytes spa)))
            (unless (eql vlan 200) (error "vlan ~S" vlan))
            "vlan 200"))
        (require! "an untagged frame still reports no VLAN"
          (multiple-value-bind (op spa sha tpa tha pad vlan)
              (arp-scan::parse-arp (make-arp-frame))
            (declare (ignore spa sha tpa tha pad))
            (unless op (error "untagged frame stopped parsing"))
            (when vlan (error "invented vlan ~S" vlan))
            "nil"))
        (require! "the capture filter admits tagged frames"
          (let ((f (arp-scan::capture-filter #(#x02 0 0 0 0 #x11))))
            (unless (search "vlan" f) (error "no vlan arm: ~A" f))
            f)))

      (format t "~%[18] Target specifications~%")
      (require! "a CIDR block parses to one segment"
        (let ((segs (arp-scan::parse-targets "192.168.1.0/24")))
          (unless (= 1 (length segs)) (error "~D segments" (length segs)))
          (unless (= 254 (arp-scan::segments-count segs))
            (error "~D addresses" (arp-scan::segments-count segs)))
          "254 addresses"))
      (require! "a full range parses"
        (let ((segs (arp-scan::parse-targets "192.168.1.10-192.168.1.50")))
          (unless (= 41 (arp-scan::segments-count segs))
            (error "~D addresses" (arp-scan::segments-count segs)))
          "41 addresses"))
      (require! "a last-octet shorthand means the same thing"
        (unless (equal (arp-scan::parse-targets "192.168.1.10-50")
                       (arp-scan::parse-targets "192.168.1.10-192.168.1.50"))
          (error "shorthand and long form disagree"))
        "10-50 == 10-192.168.1.50")
      (require! "a single address parses"
        (let ((segs (arp-scan::parse-targets "192.168.1.5")))
          (unless (= 1 (arp-scan::segments-count segs))
            (error "~D addresses" (arp-scan::segments-count segs)))
          "1 address"))
      (require! "a comma list keeps disjoint pieces apart"
        (let ((segs (arp-scan::parse-targets "10.0.0.1-3, 10.0.5.1-2")))
          (unless (= 2 (length segs)) (error "~D segments" (length segs)))
          (unless (= 5 (arp-scan::segments-count segs))
            (error "~D addresses" (arp-scan::segments-count segs)))
          "2 segments, 5 addresses"))
      (require! "overlapping and abutting specs are merged, not scanned twice"
        (let ((segs (arp-scan::parse-targets "10.0.0.1-10,10.0.0.5-20,10.0.0.21-30")))
          (unless (= 1 (length segs))
            (error "~D segments, expected them merged" (length segs)))
          (unless (= 30 (arp-scan::segments-count segs))
            (error "~D addresses" (arp-scan::segments-count segs)))
          "1 segment, 30 addresses"))
      (require! "malformed targets are rejected"
        (dolist (bad '("10.0.0.50-10" "10.0.0.1-999" "10.0.0.1-abc" "" ","))
          (handler-case (progn (arp-scan::parse-targets bad)
                               (error "accepted ~S" bad))
            (arp-scan::invalid-target () t)))
        "5 rejected")

      (format t "~%[19] Wake-on-LAN~%")
      (require! "the magic packet has the right shape"
        (let ((frame (arp-scan::build-wol-packet #(#x02 0 0 0 0 #x11)
                                                 #(#xdc #xa6 #x32 1 2 3))))
          (unless (= 116 (length frame)) (error "~D bytes" (length frame)))
          (unless (equalp (subseq frame 0 6) #(#xdc #xa6 #x32 1 2 3))
            (error "not addressed to the target"))
          (unless (= #x0842 (u16-be frame 12)) (error "ethertype"))
          (unless (every (lambda (b) (= b #xff)) (subseq frame 14 20))
            (error "missing the 6-byte sync stream"))
          ;; Sixteen repetitions of the target MAC follow the sync stream.
          (dotimes (rep 16)
            (let ((at (+ 20 (* rep 6))))
              (unless (equalp (subseq frame at (+ at 6)) #(#xdc #xa6 #x32 1 2 3))
                (error "repetition ~D is wrong" rep))))
          "116 bytes, 16 repetitions"))

      (format t "~%[20] Hooks~%")
      (require! "a hook runs and reports success"
        (unless (arp-scan::run-hook "/usr/bin/true") (error "true failed"))
        "ran")
      (require! "a failing hook is reported, not fatal"
        (let ((noise (make-string-output-stream)))
          (let ((*error-output* noise))
            (when (arp-scan::run-hook "/usr/bin/false")
              (error "reported success for a non-zero exit")))
          "false -> nil"))
      (require! "a missing hook binary does not take the scan down"
        (let ((noise (make-string-output-stream)))
          (let ((*error-output* noise))
            (when (arp-scan::run-hook "/nonexistent/arp-scan-hook")
              (error "reported success for a missing binary")))
          "survived"))
      (require! "hook arguments are passed as argv, never through a shell"
        ;; A vendor string is attacker-chosen; if it reached a shell, this would
        ;; run the embedded command instead of passing it along as text.
        (let* ((path (merge-pathnames "arp-scan-smoke-hook-out.txt"
                                      (uiop:temporary-directory)))
               (evil (format nil "x; touch ~A" (namestring path))))
          (unwind-protect
               (progn
                 (ignore-errors (delete-file path))
                 (let ((noise (make-string-output-stream)))
                   (let ((*error-output* noise))
                     (arp-scan::run-hook "/bin/echo" evil)))
                 (when (probe-file path)
                   (error "the shell interpreted a vendor string"))
                 "argv only, no shell")
            (ignore-errors (delete-file path))))))

    (format t "~%~A~%" (if all-ok "All checks passed." "FAILED."))
    (uiop:quit (if all-ok 0 1))))
