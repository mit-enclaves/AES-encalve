# Find the Root Directory
ROOT:=$(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Define compiler
CC=riscv64-unknown-linux-gnu-gcc

OBJCOPY=riscv64-unknown-linux-gnu-objcopy

# Define Directories
API_DIR=$(ROOT)/../security_monitor/api
CLIB_DIR=$(ROOT)/../security_monitor/src/clib
ENCLAVE_SRC_DIR=$(ROOT)/src
BUILD_DIR=$(ROOT)/build

ENCLAVE_ELF = $(BUILD_DIR)/aes-enclave.elf
ENCLAVE_BIN = $(BUILD_DIR)/aes-enclave.bin

ALL=$(ENCLAVE_BIN) $(BUILD_DIR)/aes-main

all: $(ALL)

# Flags
# -mcmodel=medany is *very* important - it ensures the program addressing is PC-relative. Ensure no global variables are used. To quote from the spec, "the program and its statically defined symbols must lie within any single 2 GiB address range. Addressing for global symbols uses lui/addi instruction pairs, which emit the R_RISCV_PCREL_HI20/R_RISCV_PCREL_LO12_I sequences."
DEBUG_FLAGS = -g
CFLAGS = -march=rv64g -mcmodel=medany -mabi=lp64 -fno-common -std=gnu11 -Wall -Werror -O $(DEBUG_FLAGS)
LDFLAGS = -nostartfiles -nostdlib -static

CRYPTO_STREAM=$(ENCLAVE_SRC_DIR)/crypto_stream

#Targets
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

ENCLAVE_INCLUDES = \
	$(API_DIR) \
	$(CLIB_DIR) \
	$(ENCLAVE_SRC_DIR) \
	$(CRYPTO_STREAM)

ENCLAVE_COMMON_SRC = \
	$(ENCLAVE_SRC_DIR)/enclave_entry.S \
	$(ENCLAVE_SRC_DIR)/aes-enclave.c \
	$(ENCLAVE_SRC_DIR)/aes-enclave-key.c \
	$(CLIB_DIR)/memcpy.c \
	$(CRYPTO_STREAM)/afternm.c \
	$(CRYPTO_STREAM)/beforenm.c \
	$(CRYPTO_STREAM)/common.c \
	$(CRYPTO_STREAM)/consts.c \
	$(CRYPTO_STREAM)/int128.c \
	$(CRYPTO_STREAM)/stream.c \
	$(CRYPTO_STREAM)/xor_afternm.c \

ENCLAVE_LD = $(ENCLAVE_SRC_DIR)/enclave.lds

$(ENCLAVE_SRC_DIR)/aes-enclave-key.c:
	xxd -l 16 -g 1 -i /dev/random $@
	sed -i s/_dev_random/aes_enclave_key/ $@

$(ENCLAVE_ELF): $(ENCLAVE_COMMON_SRC) $(ENCLAVE_LD) $(BUILD_DIR)
	@echo Enclave CC $@
	@$(CC) $(CFLAGS) $(addprefix -I , $(ENCLAVE_INCLUDES)) $(LDFLAGS) -T $(ENCLAVE_LD) $< $(ENCLAVE_COMMON_SRC) -o $@

$(ENCLAVE_BIN): $(ENCLAVE_ELF)
	@echo OBJCOPY $@
	@$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata --only-section=.data --only-section=.bss $< $@

$(BUILD_DIR)/aes-main: src/aes-main.c $(BUILD_DIR)/key.txt
	@echo CC $@
	@$(CC) -O -g  $(addprefix -I , $(ENCLAVE_INCLUDES)) -std=gnu11 -Wall -Werror -o $@ $<


.PHONY: clean
clean:
	-rm -rf $(BUILD_DIR)
