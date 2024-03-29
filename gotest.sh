# run this script in project root directory

# Vet examines Go source code and reports suspicious constructs
go vet ./...

# Run all unittests, include some network tests.
# Run `go test` in `pkg/core` for only logic tests
bash gen_rsa_pair.sh > /dev/null 2>&1
go clean -testcache &&\
    go test -v ./... | grep FAIL -B 5 -A 5
