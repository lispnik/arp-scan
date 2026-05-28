(in-package #:arp-scan)

(cffi:define-foreign-library libpcap
  (:darwin "libpcap.dylib")
  (:unix (:or "libpcap.so.1" "libpcap.so.0.8" "libpcap.so"))
  (t (:default "libpcap")))

(cffi:use-foreign-library libpcap)

(defconstant +pcap-errbuf-size+ 256)

;; tv_usec is int32 on Darwin/BSD but long (8 bytes on 64-bit) on glibc Linux.
(cffi:defcstruct timeval
  (tv-sec :long)
  #+darwin (tv-usec :int32)
  #-darwin (tv-usec :long))

(cffi:defcstruct pcap-pkthdr
  (ts (:struct timeval))
  (caplen :uint32)
  (len :uint32))

(cffi:defcstruct bpf-program
  (bf-len :uint)
  (bf-insns :pointer))

(cffi:defcfun ("pcap_open_live" %pcap-open-live) :pointer
  (device :string) (snaplen :int) (promisc :int) (to-ms :int) (errbuf :pointer))

(cffi:defcfun ("pcap_close" %pcap-close) :void
  (handle :pointer))

(cffi:defcfun ("pcap_sendpacket" %pcap-sendpacket) :int
  (handle :pointer) (buf :pointer) (size :int))

(cffi:defcfun ("pcap_next_ex" %pcap-next-ex) :int
  (handle :pointer) (header :pointer) (data :pointer))

(cffi:defcfun ("pcap_compile" %pcap-compile) :int
  (handle :pointer) (fp :pointer) (str :string)
  (optimize :int) (netmask :uint32))

(cffi:defcfun ("pcap_setfilter" %pcap-setfilter) :int
  (handle :pointer) (fp :pointer))

(cffi:defcfun ("pcap_freecode" %pcap-freecode) :void
  (fp :pointer))

(cffi:defcfun ("pcap_geterr" %pcap-geterr) :string
  (handle :pointer))

(cffi:defcfun ("pcap_setnonblock" %pcap-setnonblock) :int
  (handle :pointer) (nonblock :int) (errbuf :pointer))

(cffi:defcfun ("pcap_datalink" %pcap-datalink) :int
  (handle :pointer))

(define-condition pcap-error (error)
  ((message :initarg :message :reader pcap-error-message))
  (:report (lambda (c s) (format s "libpcap error: ~A" (pcap-error-message c)))))

(defun pcap-open-live (device &key (snaplen 65535) (promisc t) (timeout-ms 100))
  "Open a live capture on DEVICE. Returns a pcap handle pointer or signals."
  (cffi:with-foreign-pointer (errbuf +pcap-errbuf-size+)
    (setf (cffi:mem-ref errbuf :char) 0)
    (let ((handle (%pcap-open-live device snaplen (if promisc 1 0) timeout-ms errbuf)))
      (when (cffi:null-pointer-p handle)
        (error 'pcap-error
               :message (cffi:foreign-string-to-lisp errbuf)))
      handle)))

(defun pcap-setfilter (handle expression &optional (netmask 0))
  (cffi:with-foreign-object (bpf '(:struct bpf-program))
    (when (/= 0 (%pcap-compile handle bpf expression 1 netmask))
      (error 'pcap-error :message (%pcap-geterr handle)))
    (unwind-protect
         (when (/= 0 (%pcap-setfilter handle bpf))
           (error 'pcap-error :message (%pcap-geterr handle)))
      (%pcap-freecode bpf))))

(defun pcap-sendpacket (handle bytes)
  "Send a byte vector on HANDLE."
  (let ((len (length bytes)))
    (cffi:with-foreign-pointer (buf len)
      (loop for i from 0 below len
            do (setf (cffi:mem-aref buf :uint8 i) (aref bytes i)))
      (when (/= 0 (%pcap-sendpacket handle buf len))
        (error 'pcap-error :message (%pcap-geterr handle))))))

(defun pcap-next-packet (handle)
  "Poll once for a packet. Returns a (SIMPLE-ARRAY (UNSIGNED-BYTE 8)) or NIL on timeout.
Signals PCAP-ERROR on a fatal libpcap error."
  (cffi:with-foreign-objects ((hdr-ptr :pointer) (data-ptr :pointer))
    (let ((rc (%pcap-next-ex handle hdr-ptr data-ptr)))
      (cond
        ((= rc 1)
         (let* ((hdr (cffi:mem-ref hdr-ptr :pointer))
                (data (cffi:mem-ref data-ptr :pointer))
                (caplen (cffi:foreign-slot-value hdr '(:struct pcap-pkthdr) 'caplen))
                (out (make-array caplen :element-type '(unsigned-byte 8))))
           (loop for i from 0 below caplen
                 do (setf (aref out i) (cffi:mem-aref data :uint8 i)))
           out))
        ((= rc 0) nil)                  ; timeout
        ((= rc -2) nil)                 ; EOF on savefile (not expected here)
        (t (error 'pcap-error :message (%pcap-geterr handle)))))))
