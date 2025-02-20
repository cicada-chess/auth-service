ifneq (,$(wildcard .env))
    include .env
    export
endif

MIGRATE=migrate -path ./migrations -database "postgres://$(DB_USERNAME):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(SSL_MODE)"
sourceToMock=internal/domain/user/interfaces/repository.go
destinationToMock=internal/domain/user/mocks/mock_repository.go

RUN_DIR = ./cmd/app

.PHONY: run 
run:
	go run $(RUN_DIR)/main.go

.PHONY: install
install:
	go mod download

.PHONY : clear
clear:
	go mod tidy

.PHONY: migrate-up
migrate-up:
	$(MIGRATE) up

.PHONY: migrate-down
migrate-down:
	$(MIGRATE) down

.PHONY: cover
cover:
	go test -short -count=1 -race -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
	rm coverage.out

.PHONY: gen
gen:
	mockgen -source=$(sourceToMock) \
	-destination=${destinationToMock}

.PHONY: test
test:
	go test -v -count=1 ./...

.PHONY: test100
test100:
	go test -v -count=100 ./...

.PHONY: race
race:
	go test -v -race -count=1 ./...

