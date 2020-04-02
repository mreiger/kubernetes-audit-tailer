BINARY := splunk-audit-webhook
MAINMODULE := github.com/metal-stack/kubernetes-splunk-audit-webhook/cmd/splunk-audit-webhook
COMMONDIR := $(or ${COMMONDIR},../builder)

include $(COMMONDIR)/Makefile.inc

.PHONY: all
all::
	go mod tidy

release:: all;
