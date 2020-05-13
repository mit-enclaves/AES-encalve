# Find the Root Directory
ROOT:=$(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Define compiler
CC=riscv64-unknown-elf-gcc

OBJCOPY=riscv64-unknown-elf-objcopy

# Flags
# -mcmodel=medany is *very* important - it ensures the program addressing is PC-relative. Ensure no global variables are used. To quote from the spec, "the program and its statically defined symbols must lie within any single 2 GiB address range. Addressing for global symbols uses lui/addi instruction pairs, which emit the R_RISCV_PCREL_HI20/R_RISCV_PCREL_LO12_I sequences."
DEBUG_FLAGS := -ggdb3
CFLAGS := -march=rv64g -mcmodel=medany -mabi=lp64 -fno-common -std=gnu11 -Wall -O0 $(DEBUG_FLAGS)
LDFLAGS := -nostartfiles -nostdlib -static

# Define Directories
API_DIR:=$(ROOT)/api
ENCLAVE_SRC_DIR:=$(ROOT)/src
BUILD_DIR:=$(ROOT)/build

#Targets
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

ENCLAVE_ELF := $(BUILD_DIR)/enclave.elf
ENCLAVE_BIN := $(BUILD_DIR)/enclave.bin

ALL:=$(ENCLAVE_BIN)

ENCLAVE_INCLUDES := \
	$(API_DIR) \
	$(ENCLAVE_SRC_DIR)

ENCLAVE_COMMON_SRC := \
	$(ENCLAVE_SRC_DIR)/enclave_entry.S \
  $(ENCLAVE_SRC_DIR)/enclave_code.c \

ENCLAVE_LD := $(ENCLAVE_SRC_DIR)/enclave.lds

$(ENCLAVE_ELF): $(ENCLAVE_COMMON_SRC) $(ENCLAVE_LD) $(BUILD_DIR)
	$(CC) $(CFLAGS) $(addprefix -I , $(ENCLAVE_INCLUDES)) $(LDFLAGS) -T $(ENCLAVE_LD) $< $(ENCLAVE_COMMON_SRC) -o $@

$(ENCLAVE_BIN): $(ENCLAVE_ELF)
	$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata --only-section=.data --only-section=.bss $< $@

.PHONY: enclave
enclave : $(ENCLAVE_BIN)

.PHONY: all
all: $(ALL)

.PHONY: clean
clean:
	-rm -rf $(BUILD_DIR)
