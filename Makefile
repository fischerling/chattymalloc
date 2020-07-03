SHELL=bash

# https://stackoverflow.com/a/39124162/194894
word-dot = $(word $2,$(subst ., ,$1))

MESON_VERSION=$(shell meson --version)
MESON_MAJOR_VERSION=$(call word-dot, $(MESON_VERSION), 1)
MESON_MINOR_VERSION=$(call word-dot, $(MESON_VERSION), 2)

.PHONY: all build builddir check check-format clean debug format release

all: release

BUILDTYPE ?= debugoptimized
BUILDDIR := build-$(BUILDTYPE)

release:
	$(MAKE) build BUILDTYPE=$@

debug:
	$(MAKE) build BUILDTYPE=$@

build: builddir
	ninja -C $(BUILDDIR)

builddir:
	[[ -d $(BUILDDIR) ]] || mkdir $(BUILDDIR)
	[[ -d build && $(shell realpath $(BUILDDIR)) == $(shell realpath build) ]] || ( \
		rm -f build && \
		ln -rs $(BUILDDIR) build && \
		meson --buildtype=$(BUILDTYPE) $(BUILDDIR) \
	)


CHECK_NINJA_TARGETS += test

# Meson >= 0.52 will automatically generate a clang-tidy target if a
# .clang-tidy file is found.
# Source version check: https://stackoverflow.com/a/3732456/194894
ifeq ($(shell [ $(MESON_MINOR_VERSION) -ge 52 ] && echo true), true)
CHECK_NINJA_TARGETS += clang-tidy
else
$(warning old mesion version $(MESON_VERSION) detected, meson >= 0.52 required for clang-tidy)
endif

check: all check-format
	ninja -C build $(CHECK_NINJA_TARGETS)

format: all
	ninja -C build clang-format
	yapf -i -p $(shell find -path "build*" -prune -o -type f -name "*.py")

check-format:
	./tools/check-format

clean:
	rm -rf build
	rm -rf build-*
