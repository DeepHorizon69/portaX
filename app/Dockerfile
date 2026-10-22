# ==============================================================================
# portaX Multi-Stage Hardened Dockerfile (portal & prober)
# ==============================================================================
# - Compiles static Go binaries with CGO_ENABLED=0, -trimpath, and stripped symbols.
# - Runs in gcr.io/distroless/static-debian12:nonroot (UID 65532:65532).
# - Contains zero shell, zero package manager, and zero ambient capabilities.
# ==============================================================================
FROM golang:1.24-alpine AS builder

WORKDIR /src
ENV GOTOOLCHAIN=auto
RUN apk add --no-cache ca-certificates tzdata git

RUN mkdir -p /out

COPY go.mod ./
COPY . .

RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test ./... -v
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/portal ./cmd/portal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/prober ./cmd/prober

# ------------------------------------------------------------------------------
# Target 1: portal (Go SSR BFF)
# ------------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS portal
WORKDIR /app
USER 65532:65532
COPY --from=builder /out/portal /app/portal
COPY --from=builder /src/web /app/web
COPY --from=builder /src/migrations /app/migrations
EXPOSE 8000
ENTRYPOINT ["/app/portal"]

# ------------------------------------------------------------------------------
# Target 2: prober (Isolated SSRF-Safe Health Checker)
# ------------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS prober
WORKDIR /app
USER 65532:65532
COPY --from=builder /out/prober /app/prober
ENTRYPOINT ["/app/prober"]
