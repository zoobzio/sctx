FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the demo
RUN cd demo && go build -o sctx-demo .

# Runtime image
FROM alpine:latest

# Install ca-certificates for TLS
RUN apk add --no-cache ca-certificates curl bash

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/demo/sctx-demo .

# Copy certificates (will be mounted as volume in docker-compose)
# COPY demo/certs ./certs

# Expose ports
EXPOSE 8080 8443 8444

# Run the demo
CMD ["./sctx-demo"]