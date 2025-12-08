
FLAGS = -std=c++23 -sUSE_SDL=2 -sUSE_SDL_MIXER=2 -O2

LDFLAGS = $(FLAGS) --embed-file assets.arc -sALLOW_MEMORY_GROWTH
SRCFLAGS = $(FLAGS) -Isrc -MMD

SRC = $(shell find src/ -type f -name "*.cpp")
OBJS = $(patsubst src/%,build/%.o,$(SRC))

SCRIPTS = $(shell find scripts -type f -name "*.py")
ASSETS = $(shell find assets -type f)

main.js main.wasm: $(OBJS) assets.arc
	emcc -o $@ $(LDFLAGS) $(OBJS)

build/%.o: src/%
	mkdir -p $(dir $@)
	emcc $(SRCFLAGS) -c -o $@ $<

assets.arc: $(SCRIPTS) $(ASSETS)
	python3 scripts/build_assets.py

clean:
	rm -rf build
	rm -f main.js main.wasm
	rm -f assets.arc

%.h:

-include $(OBJS:.o=.d)
