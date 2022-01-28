# Run a docker-compose environment of all of the required containers
up:
	@docker-compose up --build -V

down:
	@docker-compose down
