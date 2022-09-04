build:
	go build -o tb .

test:
	go test ./...

run: build
	./tb

release:
	git tag -a v0.1.1 -m "second release"
	git push origin v0.1.1
	goreleaser release --rm-dist
