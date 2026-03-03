# BUILD LAYER
# Compiles hashpipe and all pinned dependencies via the Makefile.
# Dependencies:
# - git for cloning dependency repos
# - build-base for cc, ar, make
# - autoconf/automake/libtool for mhash and libJudy
# - perl for OpenSSL's Configure
# - linux-headers for kernel headers required by some deps
FROM alpine AS build
RUN apk update && apk add --no-cache \
    git \
    build-base \
    autoconf \
    automake \
    libtool \
    perl \
    linux-headers

WORKDIR /src
RUN git clone https://github.com/Cynosureprime/hashpipe.git /src/hashpipe

WORKDIR /src/hashpipe
COPY Makefile .
RUN make deps && make

# RUNTIME LAYER
# Minimal image containing only the built binary.
FROM alpine
RUN apk update && apk add --no-cache tini

COPY --from=build /src/hashpipe/hashpipe /usr/local/bin/hashpipe

WORKDIR /data

ENTRYPOINT ["/sbin/tini", "--", "hashpipe"]
