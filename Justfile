# Generate the nod-ffi C header
cbindgen:
    cbindgen --config nod-ffi/cbindgen.toml --crate nod-ffi --output nod-ffi/include/nod.h

# Build and install the nod Python bindings (dev mode)
py-dev:
    cd nod && uv pip install -e .

# Build and install the nod Python bindings (release mode)
py-release:
    cd nod && uv pip install -e . --config-settings build-args='--release'
