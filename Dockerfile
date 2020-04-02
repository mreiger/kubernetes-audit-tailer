FROM metalstack/builder:latest as builder

FROM alpine:3.11
RUN apk add --no-cache tini ca-certificates
COPY --from=builder /work/bin/splunk-audit-webhook /splunk-audit-webhook
CMD ["/splunk-audit-webhook"]
