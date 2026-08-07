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

;;; MA-M (28-bit) and MA-S (36-bit) assignments
;;;
;;; IEEE subdivides some MA-L blocks and hands the pieces to small vendors. In
;;; oui.txt those parents read "IEEE Registration Authority" -- 424 of them --
;;; so a 24-bit lookup alone misnames every device in a subdivided block.
;;;
;;; A record spans two lines:
;;;
;;;   C8-5C-E2   (hex)              SYNERGY SYSTEMS AND SOLUTIONS
;;;   700000-7FFFFF     (base 16)   SYNERGY SYSTEMS AND SOLUTIONS
;;;
;;; The first gives the 24-bit parent, the second the range of the remaining 24
;;; bits. We do not need to be told which file is which: the width of that range
;;; *is* the prefix length (2^20 wide -> /28, 2^12 wide -> /36), so one parser
;;; reads both and files each entry under the right table.

(defun parse-base16-range (line)
  "Return (values start end vendor) for a `SSSSSS-EEEEEE (base 16) Name' line."
  (let ((dash (position #\- line))
        (marker (search "(base 16)" line)))
    (when (and dash marker (< dash marker))
      (let* ((end-stop (or (position-if-not (lambda (c) (digit-char-p c 16))
                                            line :start (1+ dash))
                           (length line)))
             (start (ignore-errors (parse-integer line :start 0 :end dash :radix 16)))
             (end (ignore-errors (parse-integer line :start (1+ dash)
                                                     :end end-stop :radix 16)))
             (tab (position #\Tab line :start marker)))
        (when (and start end tab)
          (values start end
                  (string-trim '(#\Tab #\Space #\Return)
                               (subseq line (1+ tab)))))))))

(defun load-oui-extended (pathname table-28 table-36)
  "Fold one MA-M or MA-S file into the /28 and /36 tables. Returns the count."
  (let ((prefix24 nil)
        (loaded 0))
    (when (probe-file pathname)
      (with-open-file (in pathname :external-format :latin-1)
        (loop for line = (read-line in nil nil)
              while line
              do (cond
                   ;; A `(hex)' line establishes the parent for what follows.
                   ((and (oui-line-p line) (search "(hex)" line :start2 8 :end2 16))
                    (setf prefix24 (logior (ash (parse-hex-byte line 0) 16)
                                           (ash (parse-hex-byte line 3) 8)
                                           (parse-hex-byte line 6))))
                   ((and prefix24 (search "(base 16)" line))
                    (multiple-value-bind (start end vendor) (parse-base16-range line)
                      (when (and start end vendor (> end start))
                        (let* ((width (1+ (- end start)))
                               (host-bits (1- (integer-length width)))
                               (full (logior (ash prefix24 24) start)))
                          ;; Only exact powers of two describe a prefix; anything
                          ;; else is a malformed row we would rather skip than
                          ;; file under a key that does not mean what it says.
                          (when (= width (ash 1 host-bits))
                            (case host-bits
                              (20 (setf (gethash (ash full -20) table-28) vendor)
                                  (incf loaded))
                              (12 (setf (gethash (ash full -12) table-36) vendor)
                                  (incf loaded))))))
                      (setf prefix24 nil)))))))
    loaded))

(defparameter *oui28-table* (make-hash-table :test 'eql :size 16000)
  "Hash table: 28-bit MA-M prefix (integer) -> vendor name string.")

(defparameter *oui36-table* (make-hash-table :test 'eql :size 16000)
  "Hash table: 36-bit MA-S prefix (integer) -> vendor name string.")

(defparameter *oui-extended-count*
  (+ (load-oui-extended (asdf:system-relative-pathname :arp-scan "data/mam.txt")
                        *oui28-table* *oui36-table*)
     (load-oui-extended (asdf:system-relative-pathname :arp-scan "data/oui36.txt")
                        *oui28-table* *oui36-table*))
  "How many MA-M/MA-S assignments were loaded, for the smoke test to check.")

(defun oui-lookup (mac-bytes)
  "Vendor name for MAC-BYTES, or NIL.

Longest prefix wins: a /36 assignment is more specific than the /28 containing
it, which is more specific than the /24 parent. Without this order, every device
in a subdivided block reports as \"IEEE Registration Authority\".

Returns NIL for a locally administered address rather than a misleading name --
those bits were chosen by software, so no vendor is encoded in them at all."
  (unless (locally-administered-p mac-bytes)
    (let ((n (mac->u48 mac-bytes)))
      (or (gethash (ash n -12) *oui36-table*)
          (gethash (ash n -20) *oui28-table*)
          (gethash (ash n -24) *oui-table*)))))
