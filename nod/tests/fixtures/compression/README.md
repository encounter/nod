These reference streams were produced by the C implementations, independently of
nod's Rust encoders. The uncompressed bytes are `b"nod pure Rust compression fixture\n"`
repeated 1024 times, followed by bytes 0 through 255 repeated 256 times.

- `reference.bz2`: Python `bz2.compress(data, compresslevel=6)` (libbzip2).
- `reference.zlib`: Python `zlib.compress(data, level=6)`.
- `reference.lzma` / `reference.lzma2`: Python `lzma.compress(data, format=FORMAT_RAW,
  filters=[{"id": FILTER_LZMA1 or FILTER_LZMA2, "preset": 6}])` (liblzma).
  The WIA properties are `5d 00 00 80 00` and `16` respectively.
- `reference.zst`: `zstd -q -c -6 input` (libzstd 1.5.7), with content size and checksum.
- `unknown-size.zst`: `zstd -q -c --no-content-size`, with the input on stdin.

The fixtures contain generated test data only. Native tools are not required to
run the tests.
