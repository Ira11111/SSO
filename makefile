.PHONY: $(MAKECMDGOALS)

run:
	go run ./cmd/sso/main.go
build:
	go build ./cmd/sso/main.go

migrate_up:
	goose -dir=/migrations postgres "host=localhost port=5432 user=postgres password=${PASS} dbname=postgres sslmode=disable" up
migrate_down:
	goose -dir=/migrations postgres "host=localhost port=5432 user=postgres password=${PASS} dbname=postgres sslmode=disable" down

app_for_test:
	CONFIG_PATH=./config/tests.yaml DB_PASS=TEST go run ./cmd/sso/main.go

test: migrate_test_up
	DB_PASS=TEST go test -v ./tests
	go clean -testcache

migrate_test_up:
	@goose -dir=./tests/migrations postgres "host=localhost port=5432 user=test password=TEST dbname=test sslmode=disable" up
migrate_test_down:
	@goose -dir=./tests/migrations postgres "host=localhost port=5432 user=test password=TEST dbname=test sslmode=disable" down
