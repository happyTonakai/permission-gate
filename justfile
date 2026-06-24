# Permission Gate — build & install
# Requires: Go 1.25+, just 1.x

binary := "pgate"
install_dir := env_var("HOME") + "/.local/bin"

# Build binary
build:
    go build -o {{ binary }} ./cmd/pgate

# Build and install to ~/.local/bin
install: build
    mkdir -p {{ install_dir }}
    cp {{ binary }} {{ install_dir }}/
    @echo "Installed to {{ install_dir }}/{{ binary }}"

install-all: install
    {{ binary }} hook install pi
    {{ binary }} hook install opencode
    {{ binary }} hook install claude-code

# Run tests
test:
    go test ./...

# Run tests with verbose output
test-verbose:
    go test -v ./...

# Run all tests with race detection
test-race:
    go test -race ./...

# Clean build artifacts
clean:
    rm -f {{ binary }}
    rm -f cmd/pgate/{{ binary }}
    rm -f cmd/batch-compare/batch-compare

# Remove installed binary
uninstall:
    rm -f {{ install_dir }}/{{ binary }}

# Lint with staticcheck
lint:
    staticcheck ./...

# Format code
fmt:
    go fmt ./...

# Run all checks (fmt + test + build)
check: fmt test build
    @echo "All checks passed"

# Show binary size
size: build
    @ls -lh {{ binary }}
