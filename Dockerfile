FROM scratch

ARG TARGETARCH

WORKDIR /app
COPY ca-certificates.crt /etc/ssl/certs/
COPY kube-auth-proxy-${TARGETARCH} /usr/bin/kube-auth-proxy
ENTRYPOINT ["kube-auth-proxy"]