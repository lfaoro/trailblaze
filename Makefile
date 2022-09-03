build:
	go build -o tb .

test:
	go test ./...

run: build
	./tb
