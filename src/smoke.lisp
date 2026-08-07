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
                    :scope (cons (arp-scan::ip->u32 #(10 0 0 1))
                                 (arp-scan::ip->u32 #(10 0 0 9))))))
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
          (format nil "~D built" built))))

    (format t "~%~A~%" (if all-ok "All checks passed." "FAILED."))
    (uiop:quit (if all-ok 0 1))))
