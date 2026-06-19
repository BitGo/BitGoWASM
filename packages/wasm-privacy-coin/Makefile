WASM_TARGET = wasm32-unknown-unknown
WASM_DIST   = dist/wasm-privacy-coin.wasm
WASM_RES    = src/main/resources/wasm/privacy_coin.wasm

.PHONY: build
build:
	cargo build --target $(WASM_TARGET) --release
	mkdir -p dist
	cp target/$(WASM_TARGET)/release/wasm_privacy_coin.wasm $(WASM_DIST)

.PHONY: jar
jar: build
	mkdir -p src/main/resources/wasm
	cp $(WASM_DIST) $(WASM_RES)
	mvn package -DskipTests
	cp target/wasm-privacy-coin-*.jar dist/wasm-privacy-coin.jar

.PHONY: test-java
test-java:
	mkdir -p src/main/resources/wasm
	cp $(WASM_DIST) $(WASM_RES)
	mvn test

.PHONY: clean
clean:
	cargo clean
	rm -rf dist src/main/resources/wasm
	mvn clean 2>/dev/null || true
