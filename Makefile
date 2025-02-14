ifneq (,$(wildcard .env))
    include .env
    export
endif

MIGRATE=migrate -path ./migrations -database "postgres://$(DB_USERNAME):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(SSL_MODE)"


RUN_DIR = ./cmd/app

.PHONY: run install clear

run:
	go run $(RUN_DIR)/main.go

install:
	go mod download

clear:
	go mod tidy

migrate-up:
	$(MIGRATE) up

migrate-down:
	$(MIGRATE) down