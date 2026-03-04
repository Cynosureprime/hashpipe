# BUILD LAYER
# Compiles hashpipe and all pinned dependencies via the Makefile.
#
# Dependencies:
# - git for cloning dependency repos
# - build-essential for cc, ar, make
# - autoconf/automake/libtool for mhash and libJudy
# - perl for OpenSSL's Configure
FROM ubuntu:22.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    autoconf \
    automake \
    libtool \
    perl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/Cynosureprime/hashpipe.git /src/hashpipe

WORKDIR /src/hashpipe
COPY Makefile .
RUN make deps && make

# RUNTIME LAYER
# Minimal image containing only the built binary.
FROM alpine
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/hashpipe/hashpipe /usr/local/bin/hashpipe

WORKDIR /data

ENTRYPOINT ["tini", "--", "hashpipe"]
