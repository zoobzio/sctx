FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY ../../.. /build
RUN cd demo/services/order-service && go build -o order-service . && ls -la order-service

FROM alpine:latest
RUN apk --no-cache add ca-certificates curl
WORKDIR /app
COPY --from=builder /build/demo/services/order-service/order-service .
RUN ls -la && chmod +x order-service
EXPOSE 8080
CMD ["./order-service"]