# Balor build helpers
# Author: Eduard Gevorkyan (egevorky@arencloud.com)
# License: Apache 2.0

SHELL := /bin/bash

ADMIN_DIST ?= admin/dist
BALOR_DEFAULT_ADMIN_PASSWORD ?= admin

.PHONY: all ui ui-dev backend admin-check run fmt clean

all: run

# Build the Yew admin UI (WASM) into admin/dist
ui:
	cd admin && trunk build --release

# Serve the UI in dev mode (trunk serve)
ui-dev:
	cd admin && trunk serve

# Check the backend only
backend:
	cargo check -p backend

# Check the admin crate for wasm target
admin-check:
	cargo check -p admin --target wasm32-unknown-unknown

# Format workspace
fmt:
	cargo fmt --all

# Build UI then run backend serving the latest dist
run: ui
	BALOR_ADMIN_DIST=$(ADMIN_DIST) \
	BALOR_DEFAULT_ADMIN_PASSWORD=$(BALOR_DEFAULT_ADMIN_PASSWORD) \
	cargo run -p backend

clean:
	cargo clean
	rm -rf admin/dist admin/pkg admin/target
