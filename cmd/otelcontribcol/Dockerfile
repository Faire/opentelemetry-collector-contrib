FROM alpine:latest AS prep
RUN apk --update add ca-certificates

FROM scratch

ARG USER_UID=10001
USER ${USER_UID}

COPY --from=prep /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY otelcol-contrib /
EXPOSE 4317 55680 55679
ENTRYPOINT ["/otelcol-contrib"]
CMD ["--config", "/etc/otel/config.yaml"]
