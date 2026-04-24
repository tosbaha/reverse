# Build four versions of the weak-RNG RSA factoring demo.
#
# Targets:
#   multi - baseline, uses GMP for all hot-loop arithmetic
#   fast  - native 64-bit limb math, GMP only for the cold path
#   neon  - fast + 4-wide NEON LCG (Apple Silicon only)
#   gpu   - Metal compute shader, one GPU thread per seed (Apple Silicon only)
#
# Requires Homebrew GMP: `brew install gmp`

GMP_PREFIX ?= /opt/homebrew/opt/gmp
GMP_INC    := -I$(GMP_PREFIX)/include
GMP_LIB    := -L$(GMP_PREFIX)/lib -lgmp

CXX        ?= g++
CXXSTD     := -std=c++17
OPT        := -O3 -march=native -flto

CXXFLAGS   := $(CXXSTD) $(OPT) $(GMP_INC)
LDFLAGS    := $(GMP_LIB)

# Metal/ObjC++ toolchain for the GPU target
OBJCXX        ?= clang++
OBJCXXFLAGS   := $(CXXSTD) -O3 -fobjc-arc $(GMP_INC)
METAL_FRAMEWORKS := -framework Metal -framework Foundation

BINS := multi fast neon gpu

.PHONY: all clean run bench

all: $(BINS)

multi: multi.cpp
	$(CXX) $(CXXFLAGS) -ffast-math $< -o $@ $(LDFLAGS)

fast: fast.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

neon: neon.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

gpu: gpu.mm
	$(OBJCXX) $(OBJCXXFLAGS) $(METAL_FRAMEWORKS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BINS)

# Run each binary once (quick smoke test).
run: all
	@for b in $(BINS); do \
		echo "=== $$b ==="; \
		./$$b; \
		echo; \
	done

# Three runs of each, reporting wall time only.
bench: all
	@for b in $(BINS); do \
		echo "=== $$b ==="; \
		for i in 1 2 3; do \
			/usr/bin/time -p ./$$b > /dev/null 2>.time; \
			awk '/real/{print $$2 "s"}' .time; \
		done; \
	done; \
	rm -f .time
