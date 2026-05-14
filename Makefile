CC = gcc
CLANG = clang
AR = ar

# libs/lib is copied from the build host. Those .so files need libc as new as
# the host that produced them — not newer than each deploy machine. If a device
# errors with GLIBC_2.xx not found, rebuild on the oldest Ubuntu you deploy to
# (or a VM/chroot matching that device), then copy bin/ + libs/ from there.
#
# Ubuntu 22.04 targets: `make build-on-2204` builds in ubuntu:22.04 (Docker) and
# copies bin/ + libs/ here — use that when your PC is newer than jammy.
LIBS_ROOT := $(abspath libs)

DOCKERFILE_2204 := $(CURDIR)/docker/Dockerfile.ubuntu-22.04
DOCKER_TAG_2204 ?= network-encryptor:ubuntu-22.04-build
# e.g. Apple Silicon → amd64 NE: make build-on-2204 DOCKER_PLATFORM=--platform=linux/amd64
DOCKER_PLATFORM ?=

ifeq ($(SKIP_LIBS),1)
LIB_PREREQ :=
LDFLAGS_LIBS := -L/usr/local/lib
BPF_LOCAL_INC :=
else
LIB_PREREQ := $(LIBS_ROOT)/.ready
LDFLAGS_LIBS := -L$(LIBS_ROOT)/lib -Wl,-rpath,'$$ORIGIN/../libs/lib' -Wl,--disable-new-dtags -L/usr/local/lib
BPF_LOCAL_INC := -I$(LIBS_ROOT)/include
endif

PG_INC := $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})

CFLAGS = -D_GNU_SOURCE -Iinc $(PG_INC) -I/usr/local/include -Wall -O2
LDFLAGS = $(LDFLAGS_LIBS) -lxdp -lbpf -lpthread -lssl -lcrypto -lpq

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin
OBJ_DIR = build

APP_SRC = main.c src/core/main_diag.c src/core/interface.c src/core/forwarder.c src/crypto/crypto_policy_utils.c src/crypto/crypto_dispatch.c src/crypto/packet_crypto.c src/crypto/crypto_layer2.c src/crypto/crypto_layer3.c src/crypto/crypto_layer4.c src/core/flow_table.c src/core/fragment.c
APP_OBJ = $(APP_SRC:.c=.o)
TARGET = $(BIN_DIR)/network-encryptor
DB_LIB_SRC = src/db/config.c src/db/db_config.c src/db/db_env.c src/db/db_runtime.c
DB_LIB_OBJ = $(DB_LIB_SRC:.c=.o)
DB_LIB = $(OBJ_DIR)/libdb_loader.a

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

MAKEFLAGS += --no-print-directory

.PHONY: all libs-clean libs-glibc-report verify-libs build-on-2204 clean run dirs

all: $(LIB_PREREQ) dirs $(BPF_OBJ) $(DB_LIB) $(TARGET)

$(LIBS_ROOT)/.ready:
	@test -f "$(CURDIR)/sh/sync_xdp_libs.sh" || (echo "[FATAL] missing $(CURDIR)/sh/sync_xdp_libs.sh" >&2; exit 127)
	@fline=$$(head -n1 "$(CURDIR)/sh/sync_xdp_libs.sh" | tr -d '\r'); \
	case "$$fline" in \
	  '#!/usr/bin/env bash'|'#!/bin/bash'*) ;; \
	  *) echo "[FATAL] sh/sync_xdp_libs.sh must start with a bash shebang (got: $$fline)." >&2; \
	     echo "[FATAL] It is often overwritten by mistake. Restore: git checkout -- sh/sync_xdp_libs.sh" >&2; exit 1;; \
	esac
	@bash "$(CURDIR)/sh/sync_xdp_libs.sh"

libs-clean:
	rm -rf "$(LIBS_ROOT)/include" "$(LIBS_ROOT)/lib" "$(LIBS_ROOT)/.ready" "$(LIBS_ROOT)/.sync_host_glibc.txt"

# Compare host libc vs symbols bundled libxdp needs (max GLIBC_* must be <= target).
libs-glibc-report:
	@echo "Host libc: $$(getconf GNU_LIBC_VERSION 2>/dev/null || ldd --version 2>&1 | sed -n '1p')"
	@test -f "$(LIBS_ROOT)/lib/libxdp.so.1" || (echo "No bundled lib yet; run make first." >&2; exit 1)
	@echo "GLIBC_* referenced by bundled libxdp.so.1 (highest must exist on deploy box):" && strings "$(LIBS_ROOT)/lib/libxdp.so.1" | grep '^GLIBC_' | sort -uV

# Run on deploy machine (e.g. NE1): fails if libs/lib was bundled on newer glibc than this host.
verify-libs:
	@bash "$(CURDIR)/sh/verify_bundled_glibc.sh"

# Build inside ubuntu:22.04; copies bin/network-encryptor + libs/ into this tree.
build-on-2204:
	@test -f "$(DOCKERFILE_2204)" || (echo "[FATAL] missing $(DOCKERFILE_2204)" >&2; exit 1)
	@command -v docker >/dev/null 2>&1 || (echo "[FATAL] install docker.io (or Docker Engine)" >&2; exit 1)
	docker build $(DOCKER_PLATFORM) -f "$(DOCKERFILE_2204)" -t "$(DOCKER_TAG_2204)" "$(CURDIR)"
	docker run --rm -v "$(CURDIR):/host:rw" "$(DOCKER_TAG_2204)" sh -ec '\
	  install -d /host/bin /host/libs; \
	  cp -a /build/bin/network-encryptor /host/bin/; \
	  rm -rf /host/libs/include /host/libs/lib /host/libs/.ready; \
	  mkdir -p /host/libs; \
	  test -d /build/libs/lib && cp -a /build/libs/include /build/libs/lib /build/libs/.ready /host/libs/; \
	  echo "Wrote bin/network-encryptor and libs/ (Ubuntu 22.04 / jammy glibc)."'

dirs:
	@mkdir -p $(BIN_DIR) $(OBJ_DIR)

$(DB_LIB): $(DB_LIB_OBJ)
	$(AR) rcs $@ $(DB_LIB_OBJ)

$(TARGET): $(APP_OBJ) $(DB_LIB)
	$(CC) -o $@ $(APP_OBJ) $(DB_LIB) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) $(BPF_LOCAL_INC) -I/usr/local/include -c $< -o $@

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR) src/*.o src/core/*.o src/crypto/*.o src/db/*.o *.o $(BPF_OBJ)

run:
	sudo DB_URL="host=localhost user=postgres dbname=xdpdb" $(TARGET) -id 30
