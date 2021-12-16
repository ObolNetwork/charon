# Run a docker-compose environment of all of the required containers
up:
	@docker-compose up --build -V

down:
	@docker-compose down

.PHONY: gen
gen: buf-generate

# Builds the Protobuf files using https://buf.build
.PHONY: buf-generate
buf-generate:
	buf generate
