#!/bin/bash

wsm="./arrow-ints2zeek.wasm"

run_wasi() {
	wasmtime \
		run \
		"${wsm}"
}

echo printing the compressed...
run_wasi | xxd
echo

echo printing the contents...
run_wasi | zstdcat | xxd
echo
