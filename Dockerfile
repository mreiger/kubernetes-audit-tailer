FROM metalstack/builder:latest as builder

FROM alpine:3.11
RUN apk add --no-cache tini ca-certificates
COPY --from=builder /work/bin/kubernetes-audit-tailer /kubernetes-audit-tailer
CMD ["/kubernetes-audit-tailer"]
