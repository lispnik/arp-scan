(in-package #:arp-scan)

;;; Running a command when something happens.
;;;
;;; Watch mode and baselines report what changed; without this they still
;;; require somebody to be reading the output. A hook is what turns them into an
;;; alarm -- notify, curl a webhook, append to a log -- with no consumer to
;;; write.
;;;
;;; Details are passed as separate argv entries, never through a shell. Vendor
;;; strings and hostnames come off the network and are entirely attacker-chosen;
;;; interpolating them into a command line would hand any device on the segment
;;; a way to run whatever it liked. UIOP:RUN-PROGRAM with a list and no
;;; :FORCE-SHELL executes the file directly, so the arguments are only ever
;;; arguments. Anyone who wants shell processing can point the hook at their own
;;; script and get it there, deliberately.

(defun run-hook (command &rest args)
  "Run COMMAND with ARGS. Returns T if it ran and exited zero.

A hook that fails must not take the scan down with it, so everything here is
contained: a missing binary, a non-zero exit and a crash are all reported and
stepped over."
  (when command
    (handler-case
        (multiple-value-bind (out err code)
            (uiop:run-program (cons command (mapcar #'princ-to-string args))
                              :output :string :error-output :string
                              :ignore-error-status t)
          (declare (ignore out))
          (cond ((zerop code) t)
                (t (format *error-output* "~&hook ~S exited ~D~@[: ~A~]~%"
                           command code
                           (let ((e (string-trim '(#\Newline #\Space) err)))
                             (unless (zerop (length e)) e)))
                   nil)))
      (error (e)
        (format *error-output* "~&hook ~S failed to run: ~A~%" command e)
        nil))))

(defun host-hook (command host &optional (event "new"))
  "Fire a host hook: COMMAND EVENT IP MAC VENDOR KIND VLAN."
  (run-hook command event
            (format-ip (host-ip host))
            (format-mac (host-mac host))
            (or (host-vendor host) "")
            (string-downcase (host-kind host))
            (or (host-vlan host) "")))

(defun anomaly-hook (command anomaly)
  "Fire an anomaly hook: COMMAND KIND IP MAC OTHER-MAC DETAIL."
  (run-hook command
            (string-downcase (anomaly-kind anomaly))
            (if (anomaly-ip anomaly) (format-ip (anomaly-ip anomaly)) "")
            (if (anomaly-mac anomaly) (format-mac (anomaly-mac anomaly)) "")
            (if (anomaly-other-mac anomaly) (format-mac (anomaly-other-mac anomaly)) "")
            (or (anomaly-detail anomaly) "")))
