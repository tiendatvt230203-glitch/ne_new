CC = gcc
CLANG = clang
AR = ar

VENDOR_ROOT := $(abspath vendor)

ifndef SKIP_VENDOR
ifneq ($(wildcard $(VENDOR_ROOT)/.use_vendor),)
USE_VENDOR := 1
endif
endif

ifdef USE_VENDOR
VENDOR_LINK := -L$(VENDOR_ROOT)/lib -Wl,-rpath,'$$ORIGIN/../vendor/lib' -Wl,--disable-new-dtags -L/usr/local/lib
BPF_VENDOR_INC := -I$(VENDOR_ROOT)/include
else
VENDOR_LINK := -L/usr/local/lib
BPF_VENDOR_INC :=
endif

PG_INC := $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})

CFLAGS = -D_GNU_SOURCE -Iinc $(PG_INC) -I/usr/local/include -Wall -O2
LDFLAGS = $(VENDOR_LINK) -lxdp -lbpf -lpthread -lssl -lcrypto -lpq

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

.PHONY: all build vendor vendor-clean clean run dirs

all:
	@if [ -z "$(SKIP_VENDOR)" ] && [ ! -f "$(VENDOR_ROOT)/.use_vendor" ]; then \
	  echo "[make] vendor (first run): staging into $(VENDOR_ROOT)/"; \
	  $(MAKE) vendor; fi
	@$(MAKE) build

build: dirs $(BPF_OBJ) $(DB_LIB) $(TARGET)

vendor:
	@test -f "$(CURDIR)/sh/vendor_stage.sh" || (echo "[FATAL] Missing $(CURDIR)/sh/vendor_stage.sh — copy from repo or git pull." >&2; exit 127)
	@bash "$(CURDIR)/sh/vendor_stage.sh"

vendor-clean:
	rm -rf "$(VENDOR_ROOT)/include" "$(VENDOR_ROOT)/lib" "$(VENDOR_ROOT)/.use_vendor"

dirs:
	@mkdir -p $(BIN_DIR) $(OBJ_DIR)

$(DB_LIB): $(DB_LIB_OBJ)
	$(AR) rcs $@ $(DB_LIB_OBJ)

$(TARGET): $(APP_OBJ) $(DB_LIB)
	$(CC) -o $@ $(APP_OBJ) $(DB_LIB) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) $(BPF_VENDOR_INC) -I/usr/local/include -c $< -o $@

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR) src/*.o src/core/*.o src/crypto/*.o src/db/*.o *.o $(BPF_OBJ)

run:
	sudo DB_URL="host=localhost user=postgres dbname=xdpdb" $(TARGET) -id 30
