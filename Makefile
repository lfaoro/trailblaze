build:
	go build -o tb .

test:
	go test ./...

run: build
	./tb

release:
	git tag -a v0.1.0 -m "first release"
	git push origin v0.1.0
	goreleaser release
