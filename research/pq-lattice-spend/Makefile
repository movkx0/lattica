CC := clang
PROFILE ?= latest
ifeq ($(PROFILE),latest)
VENDOR := vendor/labrador
REVISION := c1ae0e612d5accd9e7d9d1c264951c1afe949c83
else ifeq ($(PROFILE),toolkit)
VENDOR := vendor/labrador-toolkit
REVISION := 18b6814bc81ebcdf1c6b7e033fe648d35005937d
else
$(error Unsupported research profile $(PROFILE))
endif
BUILD_DIR ?= ../../../build-lattice-$(PROFILE)
CFLAGS := -std=gnu2x -O3 -march=native -mtune=native -fwrapv -ffast-math -DNDEBUG -Wall -Wextra -I$(VENDOR) -DSCREEN_REVISION='"$(REVISION)"'
SOURCES := aesctr.c comkey.c constraints.c dachshund.c data.c fips202.c gaussian.c jlproj.c labradoodle.c labrador_core.c labrador_tail.c labrador.c ntt.c pack.c polx.c poly.c polz.c proofsystem.c randombytes.c rejection.c labrados_python.c timing.c lnp.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

.PHONY: all
all: $(BUILD_DIR)/parameter_screen

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: $(VENDOR)/%.c $(wildcard $(VENDOR)/*.h) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/parameter_screen: src/parameter_screen.c Makefile $(OBJECTS)
	$(CC) $(CFLAGS) $< $(OBJECTS) -lm -o $@
