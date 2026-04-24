# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 hexray contributors.
#
# Build CUDA microkernels into per-SM cubins and nvdisasm JSON ground-truth.
# Requires: nvcc, nvdisasm (CUDA toolkit 13.2 component packages).
#
# Layout:
#   sources/<name>.cu                -> handwritten source
#   build/sm_<arch>/<name>.cubin     -> compiled cubin
#   build/sm_<arch>/<name>.sass.json -> nvdisasm -json ground truth
#   build/sm_<arch>/<name>.ptx       -> intermediate PTX (kept for inspection)
#
# TODO(sm_90a): add sm_90a target once Hopper decode paths land.

NVCC      ?= nvcc
NVDISASM  ?= nvdisasm
SM_ARCHS  ?= 80 86 89

SRC_DIR   := sources
BUILD_DIR := build

SOURCES   := $(wildcard $(SRC_DIR)/*.cu)
NAMES     := $(notdir $(basename $(SOURCES)))

# NVCC flags: generate cubin for a single SM, no host code, deterministic-ish.
# -Xcompiler removed since we emit device-only cubin via --cubin.
NVCC_FLAGS := --cubin -std=c++17 -O2 -Xptxas -O2 --generate-line-info

# nvdisasm: emit machine-readable JSON with control-flow + encoding details.
NVDISASM_FLAGS := --print-instruction-encoding --print-line-info -json

.PHONY: all clean check dirs
.SUFFIXES:

# Keep cubins and PTX around after sass.json is produced — without this,
# `make` treats them as intermediate and deletes them once the JSON is
# built. Both are needed downstream for hexray's own decoder to run
# against them.
.PRECIOUS: $(BUILD_DIR)/sm_%.cubin $(BUILD_DIR)/sm_%.ptx
.SECONDARY:

all: $(foreach sm,$(SM_ARCHS),$(foreach n,$(NAMES),$(BUILD_DIR)/sm_$(sm)/$(n).sass.json))

dirs:
	@for sm in $(SM_ARCHS); do mkdir -p $(BUILD_DIR)/sm_$$sm; done

# Pattern rule: cubin per (name, sm).
define CUBIN_RULE
$(BUILD_DIR)/sm_$(1)/%.cubin: $(SRC_DIR)/%.cu | dirs
	$(NVCC) $(NVCC_FLAGS) -arch=sm_$(1) -o $$@ $$<

$(BUILD_DIR)/sm_$(1)/%.ptx: $(SRC_DIR)/%.cu | dirs
	$(NVCC) -ptx -std=c++17 -O2 -arch=sm_$(1) -o $$@ $$<

$(BUILD_DIR)/sm_$(1)/%.sass.json: $(BUILD_DIR)/sm_$(1)/%.cubin
	$(NVDISASM) $(NVDISASM_FLAGS) $$< > $$@
endef

$(foreach sm,$(SM_ARCHS),$(eval $(call CUBIN_RULE,$(sm))))

# check: verify every expected artifact is present and non-empty.
check: all
	@ok=1; \
	for sm in $(SM_ARCHS); do \
	  for n in $(NAMES); do \
	    for ext in cubin sass.json; do \
	      f=$(BUILD_DIR)/sm_$$sm/$$n.$$ext; \
	      if [ ! -s "$$f" ]; then \
	        echo "MISSING or EMPTY: $$f" >&2; ok=0; \
	      fi; \
	    done; \
	  done; \
	done; \
	if [ $$ok -eq 1 ]; then echo "OK: $$(echo $(NAMES) | wc -w) kernels x $$(echo $(SM_ARCHS) | wc -w) archs"; else exit 1; fi

clean:
	rm -rf $(BUILD_DIR)
