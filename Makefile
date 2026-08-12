.PHONY: fmt lint test build install clean version install-systemd install-openrc install-sysv install-runit

VERSION := $(shell cat VERSION)
LDFLAGS := -ldflags "-s -w"
PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc
INITDIR     ?= /etc/init.d
SYSTEMDDIR  ?= /etc/systemd/system
RUNITDIR    ?= /etc/sv
RUNITACTIVE ?= /var/service

version:
	@echo $(VERSION)

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
	@test -f $(DESTDIR)$(SYSCONFDIR)/nic.conf || install -Dm600 examples/nic.conf $(DESTDIR)$(SYSCONFDIR)/nic.conf
	@mkdir -p $(DESTDIR)$(SYSCONFDIR)/nic.d

install-systemd: install
	DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)" SYSTEMDDIR="$(SYSTEMDDIR)" bash init/systemd/install.sh

install-openrc: install
	install -Dm755 init/openrc/nic $(DESTDIR)$(INITDIR)/nic
	sed -i 's|@PREFIX@|$(PREFIX)|g' $(DESTDIR)$(INITDIR)/nic
	@if test -z "$(DESTDIR)"; then rc-update add nic boot; fi

install-sysv: install
	install -Dm755 init/sysv/nic $(DESTDIR)$(INITDIR)/nic
	sed -i 's|@PREFIX@|$(PREFIX)|g' $(DESTDIR)$(INITDIR)/nic
	@if test -z "$(DESTDIR)" && command -v update-rc.d >/dev/null 2>&1; then update-rc.d nic defaults; \
	elif test -z "$(DESTDIR)" && command -v chkconfig >/dev/null 2>&1; then chkconfig --add nic; fi

install-runit: install
	mkdir -p $(DESTDIR)$(RUNITDIR)/nic $(DESTDIR)$(RUNITACTIVE)
	install -Dm755 init/runit/run $(DESTDIR)$(RUNITDIR)/nic/run
	sed -i 's|@PREFIX@|$(PREFIX)|g' $(DESTDIR)$(RUNITDIR)/nic/run
	ln -sfn $(RUNITDIR)/nic $(DESTDIR)$(RUNITACTIVE)/nic

clean:
	rm -f nic
