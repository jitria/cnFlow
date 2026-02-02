FROM golang:1.24-alpine3.21 AS builder

RUN apk --no-cache update && \
    apk add --no-cache git clang llvm make gcc protobuf musl-dev alpine-sdk

RUN go install github.com/golang/protobuf/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

WORKDIR /build
COPY cnFlow/ ./

RUN go mod download
RUN CGO_ENABLED=1 CC=gcc go build -o /out/agent ./agent/main.go
RUN CGO_ENABLED=1 CC=gcc go build -o /out/manager ./manager/main.go

# --- Agent image ---
FROM alpine:3.21 AS agent
COPY --from=builder /out/agent /usr/local/bin/agent
ENTRYPOINT ["/usr/local/bin/agent"]

# --- Manager image ---
FROM alpine:3.21 AS manager
COPY --from=builder /out/manager /usr/local/bin/manager
RUN mkdir -p /data/geoip
ENV GEOIP_DB_DIR=/data/geoip
ENTRYPOINT ["/usr/local/bin/manager"]
