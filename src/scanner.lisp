(in-package #:arp-scan)

(defun now-internal ()
  (/ (get-internal-real-time) internal-time-units-per-second 1.0d0))

(defun drain-replies (handle results deadline)
  "Read packets until DEADLINE (a real-time timestamp in seconds), recording
ARP replies into the RESULTS hash table keyed by IP u32."
  (loop while (< (now-internal) deadline)
        for frame = (pcap-next-packet handle)
        when frame
          do (multiple-value-bind (spa sha) (parse-arp-reply frame)
               (when (and spa (not (gethash (ip->u32 spa) results)))
                 (setf (gethash (ip->u32 spa) results) sha)
                 (format t "~16A  ~17A  ~A~%"
                         (format-ip spa) (format-mac sha)
                         (or (oui-lookup sha) ""))
                 (force-output)))))

(defun scan (&key interface cidr (per-host-delay-us 1000) (wait-seconds 2))
  "Scan a subnet for hosts via ARP and return an alist of (ip . mac).

INTERFACE is a string like \"en0\"; defaults to the first usable interface.
CIDR is a string like \"192.168.1.0/24\"; defaults to the interface's local subnet.
PER-HOST-DELAY-US throttles the burst of outgoing requests.
WAIT-SECONDS is the additional listen window after the last request is sent."
  (let* ((iface (if interface (find-iface interface) (default-iface)))
         (src-mac (iface-mac iface))
         (src-ip  (iface-ip iface))
         (handle  (pcap-open-live (iface-name iface)
                                  :snaplen 96 :promisc nil :timeout-ms 50)))
    (unwind-protect
         (progn
           (pcap-setfilter handle "arp")
           (multiple-value-bind (first last)
               (if cidr (cidr-range cidr) (subnet-range-from-iface iface))
             (format t "Scanning ~A on ~A (~A, ~A)~%"
                     (format nil "~A - ~A" (format-ip (u32->ip first)) (format-ip (u32->ip last)))
                     (iface-name iface)
                     (format-ip src-ip)
                     (format-mac src-mac))
             (format t "~16A  ~17A  ~A~%" "IP" "MAC" "Vendor")
             (let ((results (make-hash-table)))
               (loop for u32 from first to last
                     for target = (u32->ip u32)
                     do (pcap-sendpacket handle (build-arp-request src-mac src-ip target))
                        ;; Opportunistically drain pending replies between sends.
                        (drain-replies handle results (now-internal))
                        (when (plusp per-host-delay-us)
                          (sleep (/ per-host-delay-us 1.0d6))))
               (drain-replies handle results (+ (now-internal) wait-seconds))
               (let ((alist (loop for k being the hash-keys of results
                                  collect (cons (u32->ip k) (gethash k results)))))
                 (format t "~%~D host~:P found.~%" (length alist))
                 alist))))
      (%pcap-close handle))))

(defun scan-cidr (cidr &rest args &key interface per-host-delay-us wait-seconds)
  "Convenience entry: (scan-cidr \"192.168.1.0/24\")."
  (declare (ignore interface per-host-delay-us wait-seconds))
  (apply #'scan :cidr cidr args))
