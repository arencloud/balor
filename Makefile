# Balor build helpers
# Author: Eduard Gevorkyan (egevorky@arencloud.com)
# License: Apache 2.0

SHELL := /bin/bash

ADMIN_DIST := admin/dist

.PHONY: all ui backend run clean

all: run

# Build the Yew admin UI (WASM) into admin/dist
ui:
	cd admin && trunk build --release

# Check the backend only
backend:
	cargo check -p backend

# Build UI then run backend serving the latest dist
run: ui
	BALOR_ADMIN_DIST=$(ADMIN_DIST) cargo run -p backend

clean:
	cargo clean
	rm -rf admin/dist admin/pkg admin/target
