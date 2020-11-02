BINARY := kubernetes-audit-tailer
MAINMODULE := github.com/mreiger/kubernetes-audit-tailer/cmd/kubernetes-audit-tailer
COMMONDIR := $(or ${COMMONDIR},../builder)

include $(COMMONDIR)/Makefile.inc

.PHONY: all
all::
	go mod tidy

release:: all;
