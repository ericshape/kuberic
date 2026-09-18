FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10000 appuser

WORKDIR /app

COPY target/debug/kvstore /app/kvstore

RUN mkdir -p /var/lib/kvstore/data && \
    chown -R appuser:appuser /app /var/lib/kvstore

USER appuser

EXPOSE 8080 9090 9091

CMD ["/app/kvstore"]
