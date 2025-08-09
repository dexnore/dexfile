# syntax=docker/dockerfile:latest

ARG GO_VERSION=1.24
ARG ALPINE_VERSION=3.21
ARG XX_VERSION=1.6.1

# xx is a helper for cross-compilation
FROM --platform=$BUILDPLATFORM tonistiigi/xx:${XX_VERSION} AS xx

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS base
RUN apk add git bash
COPY --from=xx / /
WORKDIR /src
ENV GOFLAGS=-mod=vendor

FROM base AS version
ARG CHANNEL
# TODO: PKG should be inferred from go modules
RUN --mount=target=. \ 
  PKG=github.com/dexnore/dexfile VERSION=$(./hack/detect "$CHANNEL") REVISION=$(git rev-parse HEAD)$(if ! git diff --no-ext-diff --quiet --exit-code; then echo .m; fi) \
  && echo "-X dexfile.Version=${VERSION} -X dexfile.Revision=${REVISION} -X dexfile.Package=${PKG}" | tee /tmp/.ldflags \
  && echo -n "${VERSION}" | tee /tmp/.version

FROM base AS build
RUN apk add --no-cache file
ARG BUILDTAGS=""
ARG TARGETPLATFORM
RUN --mount=target=. --mount=type=cache,target=/root/.cache \
  --mount=target=/go/pkg/mod,type=cache \
  --mount=source=/tmp/.ldflags,target=/tmp/.ldflags,from=version \
  CGO_ENABLED=0 xx-go build -mod=readonly -o /dexfile-frontend -ldflags "-d $(cat /tmp/.ldflags)" -tags "$BUILDTAGS netgo static_build osusergo" ./cmd/dexfile && \
  xx-verify --static /dexfile-frontend

FROM scratch AS release
LABEL moby.buildkit.frontend.network.none="true"
LABEL moby.buildkit.frontend.caps="moby.buildkit.frontend.inputs,moby.buildkit.frontend.subrequests,moby.buildkit.frontend.contexts"
COPY --from=build /dexfile-frontend /bin/dexfile-frontend
ENTRYPOINT ["/bin/dexfile-frontend"]

FROM release
