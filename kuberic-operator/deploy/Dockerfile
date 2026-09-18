FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10000 appuser

WORKDIR /app

COPY target/debug/kuberic-operator /app/kuberic-operator

RUN chown -R appuser:appuser /app

USER appuser

CMD ["/app/kuberic-operator"]
