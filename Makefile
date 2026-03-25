.PHONY: build install clean install-systemd install-openrc install-sysv install-runit

VERSION := 0.1.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
PREFIX  := /usr/local

fmt:
	go fmt ./...

lint:
	golangci-lint run

test:
	go vet -v ./...
	go test -v -race ./...

build:
	CGO_ENABLED=0 go build -trimpath $(LDFLAGS) -buildvcs=false -o nic .

install: build
	install -Dm755 nic $(DESTDIR)$(PREFIX)/sbin/nic
	@test -f /etc/nic.conf || install -Dm644 examples/nic.conf /etc/nic.conf
	@mkdir -p /etc/nic.d

install-systemd: install
	bash init/systemd/install.sh

install-openrc: install
	install -Dm755 init/openrc/nic /etc/init.d/nic
	rc-update add nic boot

install-sysv: install
	install -Dm755 init/sysv/nic /etc/init.d/nic
	@if command -v update-rc.d >/dev/null 2>&1; then update-rc.d nic defaults; \
	elif command -v chkconfig >/dev/null 2>&1; then chkconfig --add nic; fi

install-runit: install
	mkdir -p /etc/sv/nic
	install -Dm755 init/runit/run /etc/sv/nic/run
	ln -sf /etc/sv/nic /var/service/nic

clean:
	rm -f nic
