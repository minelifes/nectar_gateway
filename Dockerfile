# nectar-gateway image (multi-arch: docker buildx build --platform linux/amd64,linux/arm64 .)
# The admin UI (ui/dist, git-ignored) is built in its own stage and embedded into the binary.
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /ui/dist ./ui/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /out/nectar_gateway .

# Runs as root so it can bind 80/443 on the host network; Kubernetes drops every capability
# except NET_BIND_SERVICE (see nectar_apps deploy/manifests/10-gateway.yaml).
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/nectar_gateway /usr/local/bin/nectar_gateway
ENV PROXY_ADDR=:80 HTTPS_ADDR=:443 ADMIN_ADDR=:8081 DB_PATH=/data/nectar.db
VOLUME ["/data"]
EXPOSE 80 443 8081
ENTRYPOINT ["/usr/local/bin/nectar_gateway"]
