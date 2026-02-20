# SDL3 IOStream Demo for nod-ffi

This demo opens a disc image via `SDL_IOStream` and passes it to `nod_disc_open_stream`.
It iterates the data partition FST, opens file entries, and prints the first bytes of each file using zero-copy reads (`nod_buf_read` + `nod_buf_consume`).

This demonstrates how to integrate nod with _non-filesystem_ data sources. If you simply want to read from the filesystem, `nod_disc_open` is more straightforward and efficient.

## Prerequisites

- Rust toolchain
- CMake 3.23+
- SDL3 development package

## Build

```bash
# From the repository root:
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target nod_sdl3_stream_demo
```

## Run

```bash
./build/nod-ffi/examples/sdl3-stream-demo/nod_sdl3_stream_demo "/path/to/disc.rvz"
```
