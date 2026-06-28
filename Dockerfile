FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o nullfinder ./cmd/nullfinder

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/nullfinder /usr/local/bin/nullfinder

ENTRYPOINT ["nullfinder"]
