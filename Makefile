.PHONY: charon go-setup clean

all: clean charon

go-setup:
	go mod tidy

charon: go-setup
	go build -trimpath -ldflags="-buildid= -s -w -X github.com/obolnetwork/charon/app/version.version=$(shell bash charon_version.sh)"

clean:
	$(RM) charon
