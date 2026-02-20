#ifndef NOD_H
#define NOD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/**
 * Wii disc magic bytes at offset 0x18.
 */
#define WII_MAGIC ((const uint8_t[4]){0x5D, 0x1C, 0x9E, 0xA3})

/**
 * GameCube disc magic bytes at offset 0x1C.
 */
#define GCN_MAGIC ((const uint8_t[4]){0xC2, 0x33, 0x9F, 0x3D})

/**
 * Compares two 4-byte magic values.
 */
#define NOD_MAGIC_EQ(lhs, rhs) ((lhs)[0] == (rhs)[0] && (lhs)[1] == (rhs)[1] && (lhs)[2] == (rhs)[2] && (lhs)[3] == (rhs)[3])


/**
 * Partition kind: data partition.
 */
#define NOD_PARTITION_KIND_DATA 0

/**
 * Partition kind: update partition.
 */
#define NOD_PARTITION_KIND_UPDATE 1

/**
 * Partition kind: channel partition.
 */
#define NOD_PARTITION_KIND_CHANNEL 2

/**
 * Sentinel value: `nod_partition_find_file` returns this when a file is not found.
 * `nod_partition_iterate_fst` callback returns this to stop iteration.
 */
#define NOD_FST_STOP UINT32_MAX

/**
 * Result codes returned by nod FFI functions.
 */
typedef enum NodResult {
  /**
   * Operation succeeded.
   */
  NOD_RESULT_OK,
  /**
   * An I/O error occurred.
   */
  NOD_RESULT_ERR_IO,
  /**
   * The disc format is invalid or unsupported.
   */
  NOD_RESULT_ERR_FORMAT,
  /**
   * The requested item was not found.
   */
  NOD_RESULT_ERR_NOT_FOUND,
  /**
   * The provided handle is null or of the wrong type.
   */
  NOD_RESULT_ERR_INVALID_HANDLE,
  /**
   * An unclassified error occurred.
   */
  NOD_RESULT_ERR_OTHER,
} NodResult;

/**
 * Partition encryption mode.
 */
typedef enum NodPartitionEncryption {
  /**
   * Partition encryption and hashes are rebuilt to match the original state,
   * if necessary. This is used for converting or verifying a disc image.
   */
  NOD_PARTITION_ENCRYPTION_ORIGINAL,
  /**
   * Partition data will be encrypted if reading a decrypted disc image.
   * Modifies the disc header to mark partition data as encrypted.
   */
  NOD_PARTITION_ENCRYPTION_FORCE_ENCRYPTED,
  /**
   * Partition data will be decrypted if reading an encrypted disc image.
   * Modifies the disc header to mark partition data as decrypted.
   */
  NOD_PARTITION_ENCRYPTION_FORCE_DECRYPTED,
  /**
   * Partition data will be decrypted if reading an encrypted disc image.
   * Modifies the disc header to mark partition data as decrypted.
   * Hashes are removed from the partition data.
   */
  NOD_PARTITION_ENCRYPTION_FORCE_DECRYPTED_NO_HASHES,
} NodPartitionEncryption;

/**
 * Disc image format.
 */
typedef enum NodFormat {
  NOD_FORMAT_ISO,
  NOD_FORMAT_CISO,
  NOD_FORMAT_GCZ,
  NOD_FORMAT_NFS,
  NOD_FORMAT_RVZ,
  NOD_FORMAT_WBFS,
  NOD_FORMAT_WIA,
  NOD_FORMAT_TGC,
} NodFormat;

/**
 * The disc file format's compression algorithm.
 */
typedef enum NodCompressionKind {
  NOD_COMPRESSION_KIND_NONE,
  NOD_COMPRESSION_KIND_BZIP2,
  NOD_COMPRESSION_KIND_DEFLATE,
  NOD_COMPRESSION_KIND_LZMA,
  NOD_COMPRESSION_KIND_LZMA2,
  NOD_COMPRESSION_KIND_ZSTANDARD,
} NodCompressionKind;

/**
 * File system node kind.
 */
typedef enum NodNodeKind {
  NOD_NODE_KIND_FILE,
  NOD_NODE_KIND_DIRECTORY,
} NodNodeKind;

/**
 * Opaque handle representing a disc, partition, or file reader.
 */
typedef struct NodHandle NodHandle;

/**
 * Options for opening a disc image. Zero-initialization provides sensible defaults.
 */
typedef struct NodDiscOptions {
  /**
   * Wii partition encryption mode. This affects how partition data appears when
   * reading directly from the disc handle, and can be used to convert between
   * encrypted and decrypted disc images.
   */
  enum NodPartitionEncryption partition_encryption;
  /**
   * Number of threads to use for preloading data as the disc is read. This
   * is particularly useful when reading the disc image sequentially, as it
   * can perform decompression and rebuilding in parallel with the main read
   * thread. 0 disables preloading. Ignored if built without threading support.
   */
  uint32_t preloader_threads;
} NodDiscOptions;

/**
 * Reads stream data at an absolute offset.
 *
 * Returns the number of bytes read, or `-1` on error.
 */
typedef int64_t (*NodDiscStreamReadAtCallback)(void *user_data,
                                               uint64_t offset,
                                               void *out,
                                               size_t len);

/**
 * Returns the total stream length in bytes.
 *
 * Returns the length, or `-1` on error.
 */
typedef int64_t (*NodDiscStreamLenCallback)(void *user_data);

/**
 * Closes stream resources associated with `user_data`.
 */
typedef void (*NodDiscStreamCloseCallback)(void *user_data);

/**
 * Callback-backed stream descriptor for `nod_disc_open_stream`.
 *
 * All callbacks must be non-null.
 */
typedef struct NodDiscStream {
  /**
   * Opaque pointer passed to callbacks.
   */
  void *user_data;
  /**
   * Reads data from the stream at `offset` into `out`.
   */
  NodDiscStreamReadAtCallback read_at;
  /**
   * Returns the stream length in bytes.
   */
  NodDiscStreamLenCallback stream_len;
  /**
   * Callback for releasing stream resources.
   */
  NodDiscStreamCloseCallback close;
} NodDiscStream;

/**
 * Options for opening a partition. Zero-initialization provides sensible defaults.
 */
typedef struct NodPartitionOptions {
  /**
   * Wii: Validate data hashes while reading the partition, if available.
   * This significantly slows down reading.
   */
  bool validate_hashes;
} NodPartitionOptions;

/**
 * Shared GameCube & Wii disc header.
 *
 * This header is always at the start of the disc image and within each Wii partition.
 */
typedef struct NodDiscHeader {
  /**
   * Game ID (e.g. GM8E01 for Metroid Prime) (not null-terminated)
   */
  char game_id[6];
  /**
   * Used in multi-disc games
   */
  uint8_t disc_num;
  /**
   * Disc version
   */
  uint8_t disc_version;
  /**
   * Audio streaming enabled
   */
  uint8_t audio_streaming;
  /**
   * Audio streaming buffer size
   */
  uint8_t audio_stream_buf_size;
  /**
   * Padding
   */
  uint8_t _pad1[14];
  /**
   * If this is a Wii disc, this will be equal to WII_MAGIC
   */
  uint8_t wii_magic[4];
  /**
   * If this is a GameCube disc, this will be equal to GCN_MAGIC
   */
  uint8_t gcn_magic[4];
  /**
   * Game title (not null-terminated)
   */
  char game_title[64];
  /**
   * If 1, disc omits partition hashes
   */
  uint8_t no_partition_hashes;
  /**
   * If 1, disc omits partition encryption
   */
  uint8_t no_partition_encryption;
  /**
   * Padding
   */
  uint8_t _pad2[926];
} NodDiscHeader;

/**
 * Disc compression settings.
 */
typedef struct NodCompression {
  /**
   * The compression algorithm.
   */
  enum NodCompressionKind kind;
  /**
   * Compression level (0 if not applicable).
   */
  int16_t level;
} NodCompression;

/**
 * Extra metadata about the underlying disc file format.
 */
typedef struct NodDiscMeta {
  /**
   * The disc file format.
   */
  enum NodFormat format;
  /**
   * The format's compression algorithm.
   */
  struct NodCompression compression;
  /**
   * If the format uses blocks, the block size in bytes (0 if unknown).
   */
  uint32_t block_size;
  /**
   * Whether Wii partitions are stored decrypted in the format.
   */
  bool decrypted;
  /**
   * Whether the format omits Wii partition data hashes.
   */
  bool needs_hash_recovery;
  /**
   * Whether the format supports recovering the original disc data losslessly.
   */
  bool lossless;
  /**
   * The original disc's size in bytes, if stored by the format (0 if unknown).
   */
  uint64_t disc_size;
  /**
   * The original disc's CRC32 hash, if stored by the format (0 if unknown).
   */
  uint32_t crc32;
  /**
   * The original disc's MD5 hash, if stored by the format (all zeroes if unknown).
   */
  uint8_t md5[16];
  /**
   * The original disc's SHA-1 hash, if stored by the format (all zeroes if unknown).
   */
  uint8_t sha1[20];
  /**
   * The original disc's XXH64 hash, if stored by the format (0 if unknown).
   */
  uint64_t xxh64;
} NodDiscMeta;

/**
 * Partition information.
 */
typedef struct NodPartitionInfo {
  /**
   * Partition index.
   */
  uint32_t index;
  /**
   * Partition kind (0 = Data, 1 = Update, 2 = Channel, other = raw value).
   */
  uint32_t kind;
  /**
   * Data region size in bytes.
   */
  uint64_t data_size;
} NodPartitionInfo;

/**
 * Borrowed byte slice.
 *
 * The data pointer is non-owning and remains valid while the source handle is alive.
 */
typedef struct NodBlob {
  /**
   * Pointer to the first byte, or null if absent.
   */
  const uint8_t *data;
  /**
   * Number of bytes in `data`.
   */
  size_t size;
} NodBlob;

/**
 * Extra partition metadata blobs. (boot.bin, bi2.bin, apploader.bin, main.dol, etc.)
 *
 * All pointers are borrowed and valid while the source partition handle remains alive.
 */
typedef struct NodPartitionMeta {
  /**
   * Disc and boot header (boot.bin)
   */
  struct NodBlob raw_boot;
  /**
   * Debug and region information (bi2.bin)
   */
  struct NodBlob raw_bi2;
  /**
   * Apploader (apploader.bin)
   */
  struct NodBlob raw_apploader;
  /**
   * Main binary (main.dol)
   */
  struct NodBlob raw_dol;
  /**
   * File system table (fst.bin)
   */
  struct NodBlob raw_fst;
  /**
   * Ticket (ticket.bin, Wii only)
   */
  struct NodBlob raw_ticket;
  /**
   * TMD (tmd.bin, Wii only)
   */
  struct NodBlob raw_tmd;
  /**
   * Certificate chain (cert.bin, Wii only)
   */
  struct NodBlob raw_cert_chain;
  /**
   * H3 hash table (h3.bin, Wii only)
   */
  struct NodBlob raw_h3_table;
} NodPartitionMeta;

/**
 * Callback for iterating file system entries.
 *
 * Parameters:
 * - `index`: node index in the FST
 * - `kind`: whether the node is a file or directory
 * - `name`: null-terminated file/directory name
 * - `size`: file size in bytes (0 for directories)
 * - `user_data`: opaque pointer passed to `nod_partition_iterate_fst`
 *
 * Returns: the next node index to visit, or `NOD_FST_STOP` to stop.
 */
typedef uint32_t (*NodFstCallback)(uint32_t, enum NodNodeKind, const char*, uint32_t, void*);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Returns a pointer to the last error message, or null if no error has occurred.
 *
 * The returned string is valid until the next `nod_*` call on the same thread.
 */
const char *nod_error_message(void);

/**
 * Opens a disc image from a file path.
 *
 * `options` may be null to use defaults.
 *
 * On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
 * The handle must be freed with `nod_free`.
 */
enum NodResult nod_disc_open(const char *path,
                             const struct NodDiscOptions *options,
                             struct NodHandle **out);

/**
 * Opens a disc image from a callback-backed stream.
 *
 * `stream` callbacks must be valid and non-null.
 * `options` may be null to use defaults.
 *
 * On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
 * The handle must be freed with `nod_free`.
 */
enum NodResult nod_disc_open_stream(const struct NodDiscStream *stream,
                                    const struct NodDiscOptions *options,
                                    struct NodHandle **out);

/**
 * Opens a partition by index from a disc handle.
 *
 * `disc` must be a handle returned by `nod_disc_open`.
 * `options` may be null to use defaults.
 *
 * **GameCube**: `index` must always be 0.
 *
 * On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
 * The partition handle must be freed with `nod_free`.
 */
enum NodResult nod_disc_open_partition(struct NodHandle *disc,
                                       uint32_t index,
                                       const struct NodPartitionOptions *options,
                                       struct NodHandle **out);

/**
 * Opens a partition by kind from a disc handle.
 *
 * Searches for the first partition matching `kind` (0 = Data, 1 = Update, 2 = Channel).
 * `options` may be null to use defaults.
 *
 * **GameCube**: `kind` must always be `NOD_PARTITION_KIND_DATA`.
 *
 * On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
 * The partition handle must be freed with `nod_free`.
 */
enum NodResult nod_disc_open_partition_kind(struct NodHandle *disc,
                                            uint32_t kind,
                                            const struct NodPartitionOptions *options,
                                            struct NodHandle **out);

/**
 * Opens a file from a partition handle by FST node index.
 *
 * `partition` must be a handle returned by `nod_disc_open_partition` or
 * `nod_disc_open_partition_kind`.
 * On success, writes a new handle to `*out` and returns `NOD_RESULT_OK`.
 * The file handle must be freed with `nod_free`.
 */
enum NodResult nod_partition_open_file(struct NodHandle *partition,
                                       uint32_t fst_index,
                                       struct NodHandle **out);

/**
 * Frees a handle returned by any `nod_*_open*` function.
 *
 * Passing null is a no-op. After this call, the handle is invalid.
 */
void nod_free(struct NodHandle *handle);

/**
 * Reads up to `len` bytes from a handle into `buf`.
 *
 * This function may return fewer than `len` bytes even before end-of-stream.
 * Callers that need an exact byte count must loop until the buffer is filled
 * or the function returns 0 (end-of-stream) / -1 (error).
 *
 * Returns the number of bytes read, or -1 on error.
 * Returns 0 at end-of-stream.
 */
int64_t nod_read(struct NodHandle *handle, uint8_t *buf, size_t len);

/**
 * Seeks a handle to a new position.
 *
 * `whence`: 0 = from start, 1 = from current, 2 = from end.
 * Returns the new absolute position, or -1 on error.
 */
int64_t nod_seek(struct NodHandle *handle, int64_t offset, int32_t whence);

/**
 * Returns a pointer to the internal buffer and its length for zero-copy reads.
 *
 * On success, `*out_len` is set to the number of available bytes and a pointer
 * to the buffer is returned. Returns null on error or end-of-stream.
 * Call `nod_buf_consume` after processing the data.
 */
const void *nod_buf_read(struct NodHandle *handle, size_t *out_len);

/**
 * Consumes `n` bytes from the internal buffer after a `nod_buf_read` call.
 */
void nod_buf_consume(struct NodHandle *handle, size_t n);

/**
 * Copies the disc header into the provided struct.
 *
 * `disc` must be a disc handle. `out` must point to a valid `NodDiscHeader`.
 */
enum NodResult nod_disc_header(const struct NodHandle *disc, struct NodDiscHeader *out);

/**
 * Copies the disc metadata into the provided struct.
 *
 * `disc` must be a disc handle. `out` must point to a valid `NodDiscMeta`.
 */
enum NodResult nod_disc_meta(const struct NodHandle *disc, struct NodDiscMeta *out);

/**
 * Returns the disc size in bytes.
 *
 * `disc` must be a disc handle. Returns 0 if the handle is invalid.
 */
uint64_t nod_disc_size(const struct NodHandle *disc);

/**
 * Copies partition info into a caller-provided array.
 *
 * `out` is a pointer to an array of `NodPartitionInfo` with capacity `cap`.
 * Returns the total number of partitions (which may exceed `cap`).
 */
size_t nod_disc_partitions(const struct NodHandle *disc, struct NodPartitionInfo *out, size_t cap);

/**
 * Returns whether the partition is from a Wii disc.
 *
 * `partition` must be a partition handle. Returns false if the handle is invalid.
 */
bool nod_partition_is_wii(const struct NodHandle *partition);

/**
 * Copies partition metadata blob pointers and sizes into the provided struct.
 *
 * `partition` must be a partition handle. `out` must point to a valid
 * `NodPartitionMeta`. Returned pointers are borrowed and remain valid while
 * the partition handle is alive.
 */
enum NodResult nod_partition_meta(const struct NodHandle *partition, struct NodPartitionMeta *out);

/**
 * Finds a file in the partition's file system table by path.
 *
 * If found, `*out_kind` and `*out_length` are set and the FST node index is returned.
 * Returns `NOD_FST_STOP` (`UINT32_MAX`) if the file is not found.
 */
uint32_t nod_partition_find_file(const struct NodHandle *partition,
                                 const char *path,
                                 enum NodNodeKind *out_kind,
                                 uint32_t *out_length);

/**
 * Iterates over all entries in the partition's file system table.
 *
 * The callback receives each node's index, kind, name, size, and user data.
 * Return the next index to visit from the callback, or `NOD_FST_STOP` to stop.
 * For normal sequential iteration, return `index + 1`.
 * For directories, return `size` (which is the child-end index) to skip the subtree.
 */
void nod_partition_iterate_fst(const struct NodHandle *partition,
                               NodFstCallback callback,
                               void *user_data);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* NOD_H */
