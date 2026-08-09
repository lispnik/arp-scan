(defsystem "arp-scan"
  :description "ARP scanner for discovering hosts on a local Ethernet (like arp-scan the Linux util)."
  :author "Matthew Kennedy <burnsidemk@gmail.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("cffi" "alexandria" "clingon" "version-string" "bordeaux-threads")
  :serial t
  :components ((:module "data"
                :components ((:static-file "oui.txt")
                             (:static-file "mam.txt")
                             (:static-file "oui36.txt")))
               (:module "src"
                :components ((:file "package")
                             (:file "libpcap")
                             (:file "capture")
                             (:file "interface")
                             (:file "arp")
                             (:file "oui")
                             (:file "observer")
                             (:file "output")
                             (:file "baseline")
                             (:file "hooks")
                             (:file "fingerprint")
                             (:file "scanner")
                             (:file "main"))))
  :build-operation "program-op"
  :build-pathname "arp-scan"
  :entry-point "arp-scan:main")

(defsystem "arp-scan/smoke"
  :description "Sanity checks for arp-scan that do not require root."
  :license "MIT"
  :version "0.1.0"
  :depends-on ("arp-scan")
  :components ((:module "src"
                :components ((:file "smoke"))))
  :build-operation "program-op"
  :build-pathname "arp-scan-smoke"
  :entry-point "arp-scan.smoke:main")
