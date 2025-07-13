FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY . /build
RUN cd demo/services/payment-service && go build -o payment-service . && ls -la payment-service

FROM alpine:latest
RUN apk --no-cache add ca-certificates curl
WORKDIR /app
COPY --from=builder /build/demo/services/payment-service/payment-service .
RUN ls -la && chmod +x payment-service
EXPOSE 8080
CMD ["./payment-service"]