include .env
include .env.test
.PHONY: $(MAKECMDGOALS)


COMPILED ?= false
PRIVATE_KEY_PATH ?= ./private_key
PUBLIC_KEY_PATH ?= ./public_key

run:
ifeq ($(COMPILED), true)
	ifeq ($(test -f ./bin/sso), 1)
		./bin/sso
	else
		@echo "Binary not found"
	endif
else
	go run ./cmd/sso/main.go
endif

build:
	go build -o ./bin/sso ./cmd/sso/main.go

migrate_up:
	goose up
migrate_down:
	goose down-to 00001

app_for_test:
ifeq ($(COMPILED), true)
	CONFIG_PATH=./configs/tests.yaml DB_PASS=TEST ./bin/sso
else
	CONFIG_PATH=./configs/tests.yaml DB_PASS=TEST go run ./cmd/sso/main.go
endif

test: migrate_test_up
	go test -v ./tests
	go clean -testcache

migrate_test_up:
	goose -env ".env.test" up
migrate_test_down:
	goose -env ".env.test" down-to 00001

keys:
	openssl genpkey -algorithm RSA -out ${PRIVATE_KEY_PATH}.pem
	openssl rsa -pubout -in ${PRIVATE_KEY_PATH}.pem -out ${PUBLIC_KEY_PATH}.pem