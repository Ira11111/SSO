include .env
.PHONY: $(MAKECMDGOALS)


COMPILED ?= false
PRIVATE_KEY_PATH ?= ./private_key
PUBLIC_KEY_PATH ?= ./public_key

FULL_PUB_KEY_PATH = $(PUBLIC_KEY_PATH).pem
FULL_PRIVATE_KEY_PATH = $(PRIVATE_KEY_PATH).pem

run:
ifeq ($(COMPILED), true)
	ifeq ($(test -f ./bin/sso), 1)
		@JWT_PRIVATE_KEY="$$(cat $(FULL_PRIVATE_KEY_PATH))" \
        JWT_PUBLIC_KEY="$$(cat $(FULL_PUB_KEY_PATH))" \
		./bin/sso
	else
		@echo "Binary not found"
	endif
else
	@JWT_PRIVATE_KEY="$$(cat $(FULL_PRIVATE_KEY_PATH))" \
    JWT_PUBLIC_KEY="$$(cat $(FULL_PUB_KEY_PATH))" \
	go run ./cmd/sso/main.go
endif

run-docker:
	JWT_PRIVATE_KEY=$$(cat $(FULL_PRIVATE_KEY_PATH)) JWT_PUBLIC_KEY=$$(cat $(FULL_PUB_KEY_PATH)) docker-compose up

build:
	go build -o ./bin/sso ./cmd/sso/main.go

migrate_up:
	goose up
migrate_down:
	goose down-to 00001

keys:
	openssl genpkey -algorithm RSA -out ${PRIVATE_KEY_PATH}.pem
	openssl rsa -pubout -in ${PRIVATE_KEY_PATH}.pem -out ${PUBLIC_KEY_PATH}.pem

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