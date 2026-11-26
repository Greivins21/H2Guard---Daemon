FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
      ca-certificates \
      curl \
      file \
      git \
      build-essential \
      pkg-config \
      nghttp2-client \
      libssl-dev \
      libnghttp2-dev \
      golang-go \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

FROM base AS rapidreset-builder

RUN git clone https://github.com/secengjeff/rapidresetclient.git /workspace/rapidresetclient
WORKDIR /workspace/rapidresetclient

RUN go mod tidy || true
RUN go get golang.org/x/net/http2 golang.org/x/net/http2/hpack
RUN go build -o /workspace/rapidresetclient-bin

FROM base AS final

COPY --from=rapidreset-builder /workspace/rapidresetclient-bin /usr/local/bin/rapidresetclient

RUN chmod 755 /usr/local/bin/rapidresetclient && \
    which h2load && \
    which curl && \
    file /usr/local/bin/rapidresetclient

CMD ["/bin/sh"]