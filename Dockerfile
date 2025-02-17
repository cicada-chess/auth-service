FROM golang:1.24.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o user-service ./cmd/app/main.go


FROM debian:bullseye-slim

COPY --from=builder /app/user-service /app/user-service

WORKDIR /app


EXPOSE 8080


CMD ["./auth-service"]