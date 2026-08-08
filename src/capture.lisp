(in-package #:arp-scan)

;;; Background capture thread.
;;;
;;; The scanner used to poll for replies between sends, which meant frames
;;; arriving while the send loop was inside SLEEP sat in the kernel buffer until
;;; the next poll -- and were lost outright when that buffer overflowed. Here a
;;; dedicated thread drains libpcap continuously into a queue that the main
;;; thread swaps out whenever it is ready.
;;;
;;; A pcap_t may not be used from two threads at once, so the capture thread
;;; owns its handle exclusively; sending happens on a second, separate handle
;;; (see OPEN-SCAN-HANDLES in scanner.lisp). That keeps libpcap lock-free here
;;; -- the only shared state is the queue.
;;;
;;; Nothing below parses a frame or knows what ARP is, so the queue half is
;;; exercised by the smoke test without opening a handle or needing root.

(defconstant +capture-queue-limit+ 10000
  "Maximum frames held between drains. Beyond this we drop and count, rather
than letting a long passive run grow without bound.")

(defstruct capture
  handle                                ; pcap handle, or NIL for a queue-only capture
  thread
  (lock (bt:make-lock "arp-scan-capture"))
  (queue (make-array 256 :adjustable t :fill-pointer 0))
  (running-p nil)
  (dropped 0))

(defun capture-now ()
  "Monotonic seconds, the clock both send stamps and arrival stamps are read
from. Deliberately not libpcap's own timestamp: that is wall-clock, and mixing
the two clock domains would corrupt every round-trip measurement."
  (/ (get-internal-real-time) internal-time-units-per-second 1.0d0))

(defun capture-push (cap frame &optional (at (capture-now)))
  "Enqueue FRAME stamped with its arrival time. Returns T if stored, NIL if the
queue was full. The stamp is taken here, in the capture thread, rather than at
drain time -- the loop is tight enough that the error stays well under a
millisecond, whereas a drain may be up to a full pump interval later."
  (bt:with-lock-held ((capture-lock cap))
    (cond ((>= (fill-pointer (capture-queue cap)) +capture-queue-limit+)
           (incf (capture-dropped cap))
           nil)
          (t
           (vector-push-extend (cons frame at) (capture-queue cap))
           t))))

(defun capture-drain (cap)
  "Hand back every frame queued so far as a vector of (frame . arrival-time),
leaving CAP empty. Swaps in a fresh queue rather than copying, so the lock is
held for O(1).

The empty case returns a shared constant instead of allocating. This runs once
per target address, so on a large range the replacement queues were by far the
bulk of what the scan allocated -- and almost all of those drains find nothing."
  (bt:with-lock-held ((capture-lock cap))
    (if (zerop (fill-pointer (capture-queue cap)))
        #()
        (let ((frames (capture-queue cap)))
          (setf (capture-queue cap) (make-array 256 :adjustable t :fill-pointer 0))
          frames))))

(defun capture-loop (cap)
  "Body of the capture thread: pull frames until asked to stop."
  (loop while (capture-running-p cap)
        do (let ((frame (handler-case (pcap-next-packet (capture-handle cap))
                          ;; A handle closed underneath us races with the stop
                          ;; flag; treat any late error as end-of-capture rather
                          ;; than letting the thread die noisily.
                          (pcap-error () (return)))))
             (if frame
                 (capture-push cap frame)
                 ;; Non-blocking mode returns immediately when idle, so back off
                 ;; briefly instead of spinning a core.
                 (sleep 0.001)))))

(defun start-capture (handle)
  "Put HANDLE in non-blocking mode and start draining it on a background thread."
  (cffi:with-foreign-pointer (errbuf +pcap-errbuf-size+)
    (setf (cffi:mem-ref errbuf :char) 0)
    (when (= -1 (%pcap-setnonblock handle 1 errbuf))
      (error 'pcap-error :message (cffi:foreign-string-to-lisp errbuf))))
  (let ((cap (make-capture :handle handle :running-p t)))
    (setf (capture-thread cap)
          (bt:make-thread (lambda () (capture-loop cap))
                          :name "arp-scan capture"))
    cap))

(defun stop-capture (cap)
  "Signal the capture thread to finish and wait for it. Safe to call twice.
Does not close the handle -- the caller owns that, so a drain can still happen
after the thread is gone.

The join has no timeout (bordeaux-threads offers none), which is only safe
because the handle is non-blocking: every iteration of CAPTURE-LOOP returns
within about a millisecond and re-checks RUNNING-P, so there is no call for the
join to get stuck behind."
  (setf (capture-running-p cap) nil)
  (let ((thread (capture-thread cap)))
    (when (and thread (bt:thread-alive-p thread))
      (ignore-errors (bt:join-thread thread)))
    (setf (capture-thread cap) nil))
  cap)
