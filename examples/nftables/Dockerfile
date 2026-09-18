FROM golang:1.27-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /iron-proxy ./cmd/iron-proxy

FROM alpine:latest
RUN apk add --no-cache openssl
COPY --from=build /iron-proxy /usr/local/bin/iron-proxy
COPY examples/nftables/proxy.yaml /etc/iron-proxy/proxy.yaml
COPY examples/docker-compose/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
