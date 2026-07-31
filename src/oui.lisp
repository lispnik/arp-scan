(in-package #:arp-scan)

;;; OUI vendor lookup using the IEEE oui.txt database.
;;;
;;; The file is parsed once at load time and the table is captured in the
;;; dumped image, so the resulting binary has zero startup cost for lookups.
;;;
;;; oui.txt entries have the shape:
;;;   "28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd."
;;; We key by the 24-bit prefix as an EQL-hashable integer.
;;;
;;; I forget where I found it.

(defun hex-digit (c)
  (or (digit-char-p c 16)
      (error "Not a hex digit: ~S" c)))

(defun parse-hex-byte (s start)
  (logior (ash (hex-digit (char s start)) 4)
          (hex-digit (char s (1+ start)))))

(defun oui-line-p (line)
  "Cheap check that LINE starts with NN-NN-NN."
  (and (>= (length line) 8)
       (char= (char line 2) #\-)
       (char= (char line 5) #\-)
       (digit-char-p (char line 0) 16)))

(defun parse-oui-line (line)
  "Return (values prefix-int vendor-string) for a `XX-XX-XX (hex) <name>' line,
or NIL if LINE is not such a line."
  (when (and (oui-line-p line)
             (search "(hex)" line :start2 8 :end2 16))
    (let* ((b0 (parse-hex-byte line 0))
           (b1 (parse-hex-byte line 3))
           (b2 (parse-hex-byte line 6))
           (prefix (logior (ash b0 16) (ash b1 8) b2))
           (tab (position #\Tab line :start 13)))
      (when tab
        (values prefix (string-trim '(#\Tab #\Space #\Return)
                                    (subseq line (1+ tab))))))))

(defun load-oui-table (pathname)
  (let ((table (make-hash-table :test 'eql :size 40000)))
    (when (probe-file pathname)
      (with-open-file (in pathname :external-format :latin-1)
        (loop for line = (read-line in nil nil)
              while line
              do (multiple-value-bind (prefix vendor) (parse-oui-line line)
                   (when prefix
                     (setf (gethash prefix table) vendor))))))
    table))

(defparameter *oui-table*
  (load-oui-table (asdf:system-relative-pathname :arp-scan "data/oui.txt"))
  "Hash table: 24-bit OUI prefix (integer) -> vendor name string.")

(defun oui-lookup (mac-bytes)
  "Vendor name for the OUI prefix of MAC-BYTES, or NIL."
  (gethash (logior (ash (aref mac-bytes 0) 16)
                   (ash (aref mac-bytes 1) 8)
                   (aref mac-bytes 2))
           *oui-table*))
