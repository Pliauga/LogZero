FROM golang:1.22-alpine AS builder

WORKDIR /src
RUN apk --no-cache add ca-certificates git

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/logzero \
    ./cmd/logzero

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/logzero /bin/logzero

USER 65534:65534

ENTRYPOINT ["/bin/logzero"]
CMD ["--help"]
