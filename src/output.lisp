(in-package #:arp-scan)

;;; Output formats.
;;;
;;; The records are flat -- ip, mac, vendor and a few counters -- so the JSON
;;; and CSV writers here are shorter than pulling in a serialization library
;;; would be. If the shape ever grows nested, swap in shasht rather than
;;; extending these.
;;;
;;; Only text streams as results arrive. json and csv have to buffer, since
;;; neither can be closed off correctly until the last record is known; jsonl
;;; exists for the streaming case.

(defparameter *formats* '(:text :json :jsonl :csv))

(defun parse-format (string)
  (let ((kw (find-symbol (string-upcase string) :keyword)))
    (or (find kw *formats*)
        (error "Unknown format ~S. Expected one of: ~{~(~A~)~^, ~}" string *formats*))))

(defun structured-format-p (format)
  (not (eq format :text)))

(defun progress-stream (format)
  "Where banners and progress belong. Under a structured format they must not
land in stdout, or the document stops being parseable."
  (if (structured-format-p format) *error-output* *standard-output*))

;;; JSON

(defun json-escape (string stream)
  (write-char #\" stream)
  (loop for ch across string
        do (case ch
             (#\" (write-string "\\\"" stream))
             (#\\ (write-string "\\\\" stream))
             (#\Newline (write-string "\\n" stream))
             (#\Return (write-string "\\r" stream))
             (#\Tab (write-string "\\t" stream))
             (t (if (< (char-code ch) #x20)
                    (format stream "\\u~4,'0X" (char-code ch))
                    (write-char ch stream)))))
  (write-char #\" stream))

(defun hex-string (bytes)
  (with-output-to-string (s)
    (loop for b across bytes do (format s "~2,'0X" b))))

(defun host-vendor-text (host)
  "What to show in the vendor column.

A randomized MAC has no vendor and never will -- the bits were picked by
software -- so saying so beats an empty column that reads like a lookup miss."
  (or (host-vendor host)
      (case (host-kind host)
        (:randomized "(randomized MAC)")
        (:multicast "(multicast source!)")
        (t ""))))

(defun host-json (host stream &key padding)
  (write-char #\{ stream)
  (format stream "\"ip\":") (json-escape (format-ip (host-ip host)) stream)
  (format stream ",\"mac\":") (json-escape (format-mac (host-mac host)) stream)
  (format stream ",\"vendor\":")
  (if (host-vendor host)
      (json-escape (host-vendor host) stream)
      (write-string "null" stream))
  (format stream ",\"mac_kind\":") (json-escape (string-downcase (host-kind host)) stream)
  (if (host-rtt host)
      (format stream ",\"rtt_ms\":~,3F" (* 1000 (host-rtt host)))
      (format stream ",\"rtt_ms\":null"))
  (when (host-fingerprint host)
    (format stream ",\"fingerprint\":") (json-escape (host-fingerprint host) stream))
  (format stream ",\"replies\":~D,\"requests\":~D"
          (host-reply-count host) (host-request-count host))
  (format stream ",\"first_seen\":~D,\"last_seen\":~D"
          (host-first-seen host) (host-last-seen host))
  (format stream ",\"padding_kind\":") (json-escape (string-downcase (host-padding-kind host)) stream)
  (when (and padding (host-padding host))
    (format stream ",\"padding\":") (json-escape (hex-string (host-padding host)) stream))
  (when (host-alt-macs host)
    (format stream ",\"conflicting_macs\":[")
    (loop for (mac . count) in (host-alt-macs host)
          for first = t then nil
          do (unless first (write-char #\, stream))
             (format stream "{\"mac\":")
             (json-escape (format-mac mac) stream)
             (format stream ",\"count\":~D}" count))
    (write-char #\] stream))
  (write-char #\} stream))

(defun anomaly-json (a stream)
  (write-char #\{ stream)
  (format stream "\"kind\":") (json-escape (string-downcase (anomaly-kind a)) stream)
  (format stream ",\"time\":~D" (anomaly-time a))
  (when (anomaly-ip a)
    (format stream ",\"ip\":") (json-escape (format-ip (anomaly-ip a)) stream))
  (when (anomaly-mac a)
    (format stream ",\"mac\":") (json-escape (format-mac (anomaly-mac a)) stream))
  (when (anomaly-other-mac a)
    (format stream ",\"other_mac\":") (json-escape (format-mac (anomaly-other-mac a)) stream))
  (when (anomaly-detail a)
    (format stream ",\"detail\":") (json-escape (anomaly-detail a) stream))
  (write-char #\} stream))

;;; CSV

(defun csv-escape (string stream)
  (if (or (find #\, string) (find #\" string)
          (find #\Newline string) (find #\Return string))
      (progn
        (write-char #\" stream)
        (loop for ch across string
              do (when (char= ch #\") (write-char #\" stream))
                 (write-char ch stream))
        (write-char #\" stream))
      (write-string string stream)))

(defun csv-row (stream &rest fields)
  (loop for field in fields
        for first = t then nil
        do (unless first (write-char #\, stream))
           (csv-escape (princ-to-string field) stream))
  (terpri stream))

;;; Text

(defparameter *text-row-fmt* "~16A  ~17A  ~A~%")

(defun print-host-text (host &key padding rtt (stream *standard-output*))
  (format stream *text-row-fmt*
          (format-ip (host-ip host))
          (format-mac (host-mac host))
          (host-vendor-text host))
  (when (and rtt (host-rtt host))
    (format stream "~16T rtt ~,2F ms~%" (* 1000 (host-rtt host))))
  (when (and padding (host-padding host))
    (format stream "~16T padding ~(~A~): ~A~%"
            (host-padding-kind host) (hex-string (host-padding host))))
  (force-output stream))

(defun print-anomaly-text (a &key (stream *standard-output*))
  (format stream "  !! ~(~A~)~@[ ~A~]~@[ ~A~]~@[ vs ~A~] -- ~A~%"
          (anomaly-kind a)
          (when (anomaly-ip a) (format-ip (anomaly-ip a)))
          (when (anomaly-mac a) (format-mac (anomaly-mac a)))
          (when (anomaly-other-mac a) (format-mac (anomaly-other-mac a)))
          (anomaly-detail a))
  (force-output stream))

;;; Final emission

(defun emit-results (obs format &key padding anomalies-only rtt)
  "Write the collected hosts and anomalies in FORMAT to *STANDARD-OUTPUT*.
Text mode has already streamed its hosts, so it only adds the summary here."
  (let ((hosts (if anomalies-only
                   (remove-if-not #'host-alt-macs (observer-host-list obs))
                   (observer-host-list obs)))
        (anomalies (reverse (observer-anomalies obs))))
    (ecase format
      (:text
       (when anomalies
         (format t "~%Anomalies:~%")
         (dolist (a anomalies) (print-anomaly-text a)))
       (when rtt
         (let ((measured (remove nil hosts :key #'host-rtt)))
           (when measured
             (format t "~%Round-trip times (ms):~%")
             (dolist (host (sort (copy-list measured) #'< :key #'host-rtt))
               (format t "  ~16A ~,2F~%"
                       (format-ip (host-ip host)) (* 1000 (host-rtt host)))))))
       (format t "~%~D host~:P found.~%" (length hosts)))
      (:json
       (write-string "{\"hosts\":[")
       (loop for host in hosts
             for first = t then nil
             do (unless first (write-char #\,))
                (host-json host *standard-output* :padding padding))
       (write-string "],\"anomalies\":[")
       (loop for a in anomalies
             for first = t then nil
             do (unless first (write-char #\,))
                (anomaly-json a *standard-output*))
       (write-string "]}")
       (terpri))
      (:jsonl
       (dolist (host hosts)
         (host-json host *standard-output* :padding padding)
         (terpri))
       (dolist (a anomalies)
         (anomaly-json a *standard-output*)
         (terpri)))
      (:csv
       (csv-row *standard-output* "ip" "mac" "vendor" "mac_kind" "rtt_ms"
                "replies" "requests" "padding_kind" "fingerprint")
       (dolist (host hosts)
         (csv-row *standard-output*
                  (format-ip (host-ip host))
                  (format-mac (host-mac host))
                  (or (host-vendor host) "")
                  (string-downcase (host-kind host))
                  (if (host-rtt host)
                      (format nil "~,3F" (* 1000 (host-rtt host)))
                      "")
                  (host-reply-count host)
                  (host-request-count host)
                  (string-downcase (host-padding-kind host))
                  (or (host-fingerprint host) "")))))
    (force-output)
    hosts))
