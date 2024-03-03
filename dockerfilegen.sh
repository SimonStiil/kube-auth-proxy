source package.env

echo -n "FROM alpine:latest as certs
RUN apk --update add ca-certificates 
FROM ${PACKAGE_CONTAINER_BASE}
WORKDIR ${PACKAGE_CONTAINER_WORKDIR}
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY ${PACKAGE_CONTAINER_APPLICATION} ${PACKAGE_CONTAINER_DESTINATION}
LABEL org.opencontainers.image.source ${PACKAGE_CONTAINER_SOURCE}
LABEL org.opencontainers.image.licenses ${PACKAGE_CONTAINER_LICENSE}
ENTRYPOINT [\"${PACKAGE_CONTAINER_APPLICATION}\"]" >Dockerfile