# Stage 1: Build the Go application
FROM golang:1.24.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service ./cmd/app/main.go

# Stage 2: Create a minimal image
FROM debian:bullseye-slim

WORKDIR /app

COPY --from=builder /app/auth-service /app/auth-service

CMD ["./auth-service"]