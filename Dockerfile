# BUILD LAYER
# Compiles hashpipe and all pinned dependencies via the Makefile.
# Uses Debian (glibc) rather than Alpine (musl) because hashpipe
# requires iconv UTF-16LE support for NTLM and related hash types.
# Based on PR #2 by @JakeWnuk.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    git \
    autoconf \
    automake \
    libtool \
    perl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/hashpipe
COPY . .
RUN make deps && make

# RUNTIME LAYER
# Minimal image containing only the built binary.
FROM debian:bookworm-slim

COPY --from=build /src/hashpipe/hashpipe /usr/local/bin/hashpipe

WORKDIR /data

ENTRYPOINT ["hashpipe"]
