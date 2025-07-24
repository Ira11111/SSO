FROM golang:1.23.0-alpine3.20 AS builder

WORKDIR /usr/local/src
RUN apk --no-cache add bash make gcc gettext git musl-dev
COPY go.mod go.sum ./
RUN go mod download
COPY ./app ./app
RUN go build -o ./bin/sso ./app/cmd/sso/main.go

FROM alpine
RUN apk --no-cache add make bash
WORKDIR /usr/local/src
COPY --from=builder /usr/local/src/bin/sso ./

COPY ./configs ./configs
COPY .env ./
EXPOSE 44044
CMD ["./sso"]