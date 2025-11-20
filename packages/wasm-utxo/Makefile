WASM_PACK = wasm-pack
WASM_OPT = wasm-opt
WASM_PACK_FLAGS = --no-pack --weak-refs

ifdef WASM_PACK_DEV
	WASM_PACK_FLAGS += --dev
endif

define WASM_PACK_COMMAND
	$(WASM_PACK) build --no-opt --out-dir $(1) $(WASM_PACK_FLAGS) --target $(2)
endef

# run wasm-opt separately so we can pass `--enable-bulk-memory`
define WASM_OPT_COMMAND
    $(WASM_OPT) --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext -Oz $(1)/*.wasm -o $(1)/*.wasm
endef

define REMOVE_GITIGNORE
	find $(1) -name .gitignore -delete
endef

define SHOW_WASM_SIZE
	@find $(1) -name "*.wasm" -exec gzip -k {} \;
	@find $(1) -name "*.wasm" -exec du -h {} \;
	@find $(1) -name "*.wasm.gz" -exec du -h {} \;
	@find $(1) -name "*.wasm.gz" -delete
endef

define BUILD
	rm -rf $(1)
	$(call WASM_PACK_COMMAND,$(1),$(2))
	$(call WASM_OPT_COMMAND,$(1))
	$(call REMOVE_GITIGNORE,$(1))
	$(call SHOW_WASM_SIZE,$(1))
endef

.PHONY: js/wasm/
js/wasm/:
	$(call BUILD,$@,bundler)

.PHONY: dist/esm/js/wasm/
dist/esm/js/wasm/:
	$(call BUILD,$@,bundler)

.PHONY: dist/cjs/js/wasm/
dist/cjs/js/wasm/:
	$(call BUILD,$@,nodejs)

.PHONY: lint
lint:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings