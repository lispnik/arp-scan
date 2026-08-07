(in-package #:arp-scan)

;;; Known-hosts baseline.
;;;
;;; Record the devices you expect on a network, then flag anything else. On its
;;; own that is a one-shot audit; combined with watch mode it is a standing
;;; "something new just joined" alarm, which is the point.
;;;
;;; Keyed on MAC, not IP: DHCP reassigns addresses freely, so an IP says nothing
;;; about identity. A device that comes back on a new address is still the same
;;; device, and should not read as an intruder.
;;;
;;; The file is line-oriented rather than JSON. We have a JSON *writer*, but no
;;; reader, and a flat list of MACs does not justify hauling in a parser or
;;; hand-rolling one -- this format stays hand-editable, diffable, and greppable:
;;;
;;;   # comment
;;;   DC:A6:32:F7:9E:AF  192.168.1.88   Raspberry Pi Trading Ltd
;;;
;;; Only the first field is authoritative. The rest is a comment for humans,
;;; refreshed on every write.

(defstruct baseline
  (macs (make-hash-table))              ; mac-u48 -> the line's descriptive text
  (path nil))

(defun parse-mac (string)
  "Parse \"DC:A6:32:F7:9E:AF\" (or hyphen-separated) into a 6-byte vector, or NIL."
  (let ((bytes (make-array 6 :element-type '(unsigned-byte 8)))
        (n 0))
    (loop with start = 0
          for i from 0 to (length string)
          do (when (or (= i (length string))
                       (char= (char string i) #\:)
                       (char= (char string i) #\-))
               (let ((piece (subseq string start i)))
                 (unless (and (= (length piece) 2) (< n 6))
                   (return-from parse-mac nil))
                 (let ((v (ignore-errors (parse-integer piece :radix 16))))
                   (unless v (return-from parse-mac nil))
                   (setf (aref bytes n) v)
                   (incf n)))
               (setf start (1+ i))))
    (when (= n 6) bytes)))

(defun read-baseline (path)
  "Load a known-hosts file. A missing file yields an empty baseline, so the
first --baseline run against a fresh path reports everything as unknown rather
than failing."
  (let ((bl (make-baseline :path path)))
    (when (probe-file path)
      (with-open-file (in path :external-format :utf-8)
        (loop for line = (read-line in nil nil)
              while line
              do (let* ((trimmed (string-trim '(#\Space #\Tab #\Return) line))
                        (space (position-if (lambda (c) (member c '(#\Space #\Tab)))
                                            trimmed)))
                   (unless (or (zerop (length trimmed))
                               (char= (char trimmed 0) #\#))
                     (let ((mac (parse-mac (subseq trimmed 0 space))))
                       (when mac
                         (setf (gethash (mac->u48 mac) (baseline-macs bl))
                               (if space
                                   (string-left-trim '(#\Space #\Tab)
                                                     (subseq trimmed space))
                                   "")))))))))
    bl))

(defun write-baseline (path hosts)
  "Write HOSTS to PATH as the new approved set. Returns the number recorded.

Randomized MACs are left out on purpose. Recording one is worse than useless:
the device will rotate away from that address, so the entry can never match
again and becomes a permanent \"expected but not seen\" line. They are listed as
comments instead, so the file still shows what was on the network at the time."
  (let ((keep (remove :randomized hosts :key #'host-kind))
        (rotating (remove :randomized hosts :key #'host-kind :test-not #'eq)))
    (with-open-file (out path :direction :output :if-exists :supersede
                              :if-does-not-exist :create :external-format :utf-8)
      (format out "# arp-scan baseline -- one device per line, keyed on MAC.~%")
      (format out "# Columns after the MAC are for humans and are rewritten on each save.~%")
      (dolist (host keep)
        (format out "~A  ~16A  ~A~%"
                (format-mac (host-mac host))
                (format-ip (host-ip host))
                (host-vendor-text host)))
      (when rotating
        (format out "#~%# Seen but not recorded -- these addresses are randomized and will rotate:~%")
        (dolist (host rotating)
          (format out "#   ~A  ~A~%"
                  (format-mac (host-mac host)) (format-ip (host-ip host))))))
    (length keep)))

(defun baseline-known-p (bl host)
  (nth-value 1 (gethash (mac->u48 (host-mac host)) (baseline-macs bl))))

(defun unknown-hosts (bl hosts)
  "Hosts whose MAC is absent from the baseline."
  (remove-if (lambda (h) (baseline-known-p bl h)) hosts))

(defun missing-hosts (bl hosts)
  "Baseline entries that did not turn up in this scan, as (mac-u48 . description).

Worth reporting alongside the unknowns: a device that has silently stopped
appearing is as interesting as one that showed up uninvited, and on a watch run
it is often the first sign something was unplugged."
  (let ((seen (make-hash-table)))
    (dolist (h hosts)
      (setf (gethash (mac->u48 (host-mac h)) seen) t))
    (let ((missing '()))
      (maphash (lambda (key desc)
                 (unless (gethash key seen)
                   (push (cons key desc) missing)))
               (baseline-macs bl))
      (nreverse missing))))

(defun u48->mac (n)
  (let ((mac (make-array 6 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 6
          do (setf (aref mac i) (ldb (byte 8 (* 8 (- 5 i))) n)))
    mac))

(defun report-baseline (bl hosts &key (stream *standard-output*))
  "Print the baseline comparison. Returns the number of *actionable* unknowns.

Randomized MACs are counted separately and excluded from that number. A device
using privacy randomization rotates its address by design -- typically per SSID
and periodically thereafter -- so it appears under a new MAC it has never used
before, and a MAC-keyed baseline calls that an intruder every single run. Left
in, they would bury the one alert that matters under a stream of false ones, and
make --fail-on-anomaly fire constantly on any network with a phone on it."
  (let* ((all-unknown (unknown-hosts bl hosts))
         (unknown (remove :randomized all-unknown :key #'host-kind))
         (rotating (remove :randomized all-unknown :key #'host-kind :test-not #'eq))
         (missing (missing-hosts bl hosts)))
    (cond ((zerop (hash-table-count (baseline-macs bl)))
           (format stream "~&Baseline ~A is empty or absent; every host reads as new.~%"
                   (baseline-path bl)))
          (t
           (format stream "~&Baseline ~A: ~D known device~:P.~%"
                   (baseline-path bl) (hash-table-count (baseline-macs bl)))))
    (when unknown
      (format stream "~%Unknown devices (~D):~%" (length unknown))
      (dolist (host unknown)
        (format stream "  ?? ~16A ~17A ~A~%"
                (format-ip (host-ip host))
                (format-mac (host-mac host))
                (host-vendor-text host))))
    (when rotating
      (format stream "~%Unrecognized but randomized (~D) -- expected churn, not counted:~%"
              (length rotating))
      (dolist (host rotating)
        (format stream "  ~~~~ ~16A ~17A~%"
                (format-ip (host-ip host))
                (format-mac (host-mac host)))))
    (when missing
      (format stream "~%Expected but not seen (~D):~%" (length missing))
      (dolist (entry missing)
        (format stream "  -- ~17A ~A~%"
                (format-mac (u48->mac (car entry))) (cdr entry))))
    (unless (or unknown missing rotating)
      (format stream "~%Everything on the network matches the baseline.~%"))
    (force-output stream)
    (length unknown)))
