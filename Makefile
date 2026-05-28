SBCL ?= sbcl
UNAME_S := $(shell uname -s)

SBCL_BUILD := $(SBCL) --non-interactive --no-sysinit --no-userinit \
  --eval '(require :asdf)' \
  --eval '(asdf:initialize-source-registry `(:source-registry (:tree ,(uiop:getcwd)) :ignore-inherited-configuration))'

ALL := arp-scan arp-scan-smoke

.PHONY: all clean smoke setcap refresh-oui

all: $(ALL)

data/oui.txt:
	@mkdir -p data
	curl -fsSL -o $@ https://standards-oui.ieee.org/oui/oui.txt

refresh-oui:
	rm -f data/oui.txt
	$(MAKE) data/oui.txt

arp-scan: arp-scan.asd data/oui.txt $(wildcard src/*.lisp)
	$(SBCL_BUILD) --eval '(asdf:make :arp-scan)'

arp-scan-smoke: arp-scan.asd data/oui.txt $(wildcard src/*.lisp)
	$(SBCL_BUILD) --eval '(asdf:make :arp-scan/smoke)'

smoke: arp-scan-smoke
	./arp-scan-smoke

# On Linux, grant CAP_NET_RAW so the binary can capture/inject raw frames without sudo.
ifeq ($(UNAME_S),Linux)
setcap: arp-scan
	sudo setcap cap_net_raw,cap_net_admin=eip ./arp-scan
	@command -v getcap >/dev/null && getcap ./arp-scan || echo "(install libcap2-bin to verify)"
else
setcap: arp-scan
	@echo "setcap target is Linux-only; on $(UNAME_S), use sudo at runtime."
endif

clean:
	rm -rf $(ALL)
