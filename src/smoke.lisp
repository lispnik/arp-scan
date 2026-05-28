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
          "00:00:00:00:00:00")))

    (format t "~%~A~%" (if all-ok "All checks passed." "FAILED."))
    (uiop:quit (if all-ok 0 1))))
