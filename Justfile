# Generate the nod-ffi C header
cbindgen:
    cbindgen --config nod-ffi/cbindgen.toml --crate nod-ffi --output nod-ffi/include/nod.h
