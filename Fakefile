ARG GO_VERSION=1.24.5
ARG ALPINE_VERSION=3.22
ARG XX_VERSION=1.6.1

# IF RUN [ -z "gg" ] || true
#   ARG XX_VERSION=10.6.1
# ELSE
#  ARG XX_VERSION=11.6.1
# ENDIF

# xx is a helper for cross-compilation
FROM --platform=$BUILDPLATFORM tonistiigi/xx:${XX_VERSION} AS xx

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS base
RUN apk add git bash
COPY --from=xx / /
WORKDIR /src
ENV GOFLAGS=-mod=vendor

FROM alpine
ENV hello="hellow"