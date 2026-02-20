use std::ffi::{c_char, c_void};

use nod::{
    common::{Compression, Format, PartitionInfo},
    disc::fst::NodeKind,
    read::{DiscMeta, DiscOptions, PartitionEncryption, PartitionMeta, PartitionOptions},
};

/// Disc image format.
#[repr(C)]
pub enum NodFormat {
    Iso,
    Ciso,
    Gcz,
    Nfs,
    Rvz,
    Wbfs,
    Wia,
    Tgc,
}

impl From<Format> for NodFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Iso => NodFormat::Iso,
            Format::Ciso => NodFormat::Ciso,
            Format::Gcz => NodFormat::Gcz,
            Format::Nfs => NodFormat::Nfs,
            Format::Rvz => NodFormat::Rvz,
            Format::Wbfs => NodFormat::Wbfs,
            Format::Wia => NodFormat::Wia,
            Format::Tgc => NodFormat::Tgc,
        }
    }
}

/// Reads stream data at an absolute offset.
///
/// Returns the number of bytes read, or `-1` on error.
pub type NodDiscStreamReadAtCallback =
    unsafe extern "C" fn(user_data: *mut c_void, offset: u64, out: *mut c_void, len: usize) -> i64;

/// Returns the total stream length in bytes.
///
/// Returns the length, or `-1` on error.
pub type NodDiscStreamLenCallback = unsafe extern "C" fn(user_data: *mut c_void) -> i64;

/// Closes stream resources associated with `user_data`.
pub type NodDiscStreamCloseCallback = unsafe extern "C" fn(user_data: *mut c_void);

/// Callback-backed stream descriptor for `nod_disc_open_stream`.
///
/// All callbacks must be non-null.
#[repr(C)]
pub struct NodDiscStream {
    /// Opaque pointer passed to callbacks.
    pub user_data: *mut c_void,
    /// Reads data from the stream at `offset` into `out`.
    pub read_at: NodDiscStreamReadAtCallback,
    /// Returns the stream length in bytes.
    pub stream_len: NodDiscStreamLenCallback,
    /// Callback for releasing stream resources.
    pub close: NodDiscStreamCloseCallback,
}

/// Partition kind: data partition.
pub const NOD_PARTITION_KIND_DATA: u32 = 0;
/// Partition kind: update partition.
pub const NOD_PARTITION_KIND_UPDATE: u32 = 1;
/// Partition kind: channel partition.
pub const NOD_PARTITION_KIND_CHANNEL: u32 = 2;

pub(crate) fn partition_kind_to_u32(k: &nod::common::PartitionKind) -> u32 {
    match k {
        nod::common::PartitionKind::Data => NOD_PARTITION_KIND_DATA,
        nod::common::PartitionKind::Update => NOD_PARTITION_KIND_UPDATE,
        nod::common::PartitionKind::Channel => NOD_PARTITION_KIND_CHANNEL,
        nod::common::PartitionKind::Other(v) => *v,
    }
}

/// Partition encryption mode.
#[repr(C)]
#[derive(Clone, Copy)]
pub enum NodPartitionEncryption {
    /// Partition encryption and hashes are rebuilt to match the original state,
    /// if necessary. This is used for converting or verifying a disc image.
    Original,
    /// Partition data will be encrypted if reading a decrypted disc image.
    /// Modifies the disc header to mark partition data as encrypted.
    ForceEncrypted,
    /// Partition data will be decrypted if reading an encrypted disc image.
    /// Modifies the disc header to mark partition data as decrypted.
    ForceDecrypted,
    /// Partition data will be decrypted if reading an encrypted disc image.
    /// Modifies the disc header to mark partition data as decrypted.
    /// Hashes are removed from the partition data.
    ForceDecryptedNoHashes,
}

impl From<NodPartitionEncryption> for PartitionEncryption {
    fn from(e: NodPartitionEncryption) -> Self {
        match e {
            NodPartitionEncryption::Original => PartitionEncryption::Original,
            NodPartitionEncryption::ForceEncrypted => PartitionEncryption::ForceEncrypted,
            NodPartitionEncryption::ForceDecrypted => PartitionEncryption::ForceDecrypted,
            NodPartitionEncryption::ForceDecryptedNoHashes => {
                PartitionEncryption::ForceDecryptedNoHashes
            }
        }
    }
}

/// Options for opening a disc image. Zero-initialization provides sensible defaults.
#[repr(C)]
pub struct NodDiscOptions {
    /// Wii partition encryption mode. This affects how partition data appears when
    /// reading directly from the disc handle, and can be used to convert between
    /// encrypted and decrypted disc images.
    pub partition_encryption: NodPartitionEncryption,
    /// Number of threads to use for preloading data as the disc is read. This
    /// is particularly useful when reading the disc image sequentially, as it
    /// can perform decompression and rebuilding in parallel with the main read
    /// thread. 0 disables preloading. Ignored if built without threading support.
    pub preloader_threads: u32,
}

impl From<&NodDiscOptions> for DiscOptions {
    fn from(opts: &NodDiscOptions) -> Self {
        DiscOptions {
            partition_encryption: opts.partition_encryption.into(),
            #[cfg(feature = "threading")]
            preloader_threads: opts.preloader_threads as usize,
        }
    }
}

/// Options for opening a partition. Zero-initialization provides sensible defaults.
#[repr(C)]
pub struct NodPartitionOptions {
    /// Wii: Validate data hashes while reading the partition, if available.
    /// This significantly slows down reading.
    pub validate_hashes: bool,
}

impl From<&NodPartitionOptions> for PartitionOptions {
    fn from(opts: &NodPartitionOptions) -> Self {
        PartitionOptions { validate_hashes: opts.validate_hashes }
    }
}

/// File system node kind.
#[repr(C)]
pub enum NodNodeKind {
    File,
    Directory,
}

impl From<NodeKind> for NodNodeKind {
    fn from(k: NodeKind) -> Self {
        match k {
            NodeKind::File => NodNodeKind::File,
            NodeKind::Directory => NodNodeKind::Directory,
            NodeKind::Invalid => NodNodeKind::File,
        }
    }
}

/// The disc file format's compression algorithm.
#[repr(C)]
pub enum NodCompressionKind {
    None,
    Bzip2,
    Deflate,
    Lzma,
    Lzma2,
    Zstandard,
}

/// Disc compression settings.
#[repr(C)]
pub struct NodCompression {
    /// The compression algorithm.
    pub kind: NodCompressionKind,
    /// Compression level (0 if not applicable).
    pub level: i16,
}

impl From<Compression> for NodCompression {
    fn from(c: Compression) -> Self {
        match c {
            Compression::None => NodCompression { kind: NodCompressionKind::None, level: 0 },
            Compression::Bzip2(level) => {
                NodCompression { kind: NodCompressionKind::Bzip2, level: i16::from(level) }
            }
            Compression::Deflate(level) => {
                NodCompression { kind: NodCompressionKind::Deflate, level: i16::from(level) }
            }
            Compression::Lzma(level) => {
                NodCompression { kind: NodCompressionKind::Lzma, level: i16::from(level) }
            }
            Compression::Lzma2(level) => {
                NodCompression { kind: NodCompressionKind::Lzma2, level: i16::from(level) }
            }
            Compression::Zstandard(level) => {
                NodCompression { kind: NodCompressionKind::Zstandard, level: i16::from(level) }
            }
        }
    }
}

/// Shared GameCube & Wii disc header.
///
/// This header is always at the start of the disc image and within each Wii partition.
#[repr(C)]
pub struct NodDiscHeader {
    /// Game ID (e.g. GM8E01 for Metroid Prime) (not null-terminated)
    pub game_id: [c_char; 6],
    /// Used in multi-disc games
    pub disc_num: u8,
    /// Disc version
    pub disc_version: u8,
    /// Audio streaming enabled
    pub audio_streaming: u8,
    /// Audio streaming buffer size
    pub audio_stream_buf_size: u8,
    /// Padding
    pub _pad1: [u8; 14],
    /// If this is a Wii disc, this will be equal to WII_MAGIC
    pub wii_magic: [u8; 4],
    /// If this is a GameCube disc, this will be equal to GCN_MAGIC
    pub gcn_magic: [u8; 4],
    /// Game title (not null-terminated)
    pub game_title: [c_char; 64],
    /// If 1, disc omits partition hashes
    pub no_partition_hashes: u8,
    /// If 1, disc omits partition encryption
    pub no_partition_encryption: u8,
    /// Padding
    pub _pad2: [u8; 926],
}

/// Extra metadata about the underlying disc file format.
#[repr(C)]
pub struct NodDiscMeta {
    /// The disc file format.
    pub format: NodFormat,
    /// The format's compression algorithm.
    pub compression: NodCompression,
    /// If the format uses blocks, the block size in bytes (0 if unknown).
    pub block_size: u32,
    /// Whether Wii partitions are stored decrypted in the format.
    pub decrypted: bool,
    /// Whether the format omits Wii partition data hashes.
    pub needs_hash_recovery: bool,
    /// Whether the format supports recovering the original disc data losslessly.
    pub lossless: bool,
    /// The original disc's size in bytes, if stored by the format (0 if unknown).
    pub disc_size: u64,
    /// The original disc's CRC32 hash, if stored by the format (0 if unknown).
    pub crc32: u32,
    /// The original disc's MD5 hash, if stored by the format (all zeroes if unknown).
    pub md5: [u8; 16],
    /// The original disc's SHA-1 hash, if stored by the format (all zeroes if unknown).
    pub sha1: [u8; 20],
    /// The original disc's XXH64 hash, if stored by the format (0 if unknown).
    pub xxh64: u64,
}

impl From<&DiscMeta> for NodDiscMeta {
    fn from(m: &DiscMeta) -> Self {
        NodDiscMeta {
            format: m.format.into(),
            compression: m.compression.into(),
            block_size: m.block_size.unwrap_or(0),
            decrypted: m.decrypted,
            needs_hash_recovery: m.needs_hash_recovery,
            lossless: m.lossless,
            disc_size: m.disc_size.unwrap_or(0),
            crc32: m.crc32.unwrap_or(0),
            md5: m.md5.unwrap_or([0; 16]),
            sha1: m.sha1.unwrap_or([0; 20]),
            xxh64: m.xxh64.unwrap_or(0),
        }
    }
}

/// Partition information.
#[repr(C)]
pub struct NodPartitionInfo {
    /// Partition index.
    pub index: u32,
    /// Partition kind (0 = Data, 1 = Update, 2 = Channel, other = raw value).
    pub kind: u32,
    /// Data region size in bytes.
    pub data_size: u64,
}

impl From<&PartitionInfo> for NodPartitionInfo {
    fn from(p: &PartitionInfo) -> Self {
        NodPartitionInfo {
            index: p.index as u32,
            kind: partition_kind_to_u32(&p.kind),
            data_size: p.data_size(),
        }
    }
}

/// Borrowed byte slice.
///
/// The data pointer is non-owning and remains valid while the source handle is alive.
#[repr(C)]
pub struct NodBlob {
    /// Pointer to the first byte, or null if absent.
    pub data: *const u8,
    /// Number of bytes in `data`.
    pub size: usize,
}

impl NodBlob {
    #[inline]
    pub const fn null() -> Self { NodBlob { data: std::ptr::null(), size: 0 } }
}

impl From<&[u8]> for NodBlob {
    #[inline]
    fn from(value: &[u8]) -> Self { NodBlob { data: value.as_ptr(), size: value.len() } }
}

/// Extra partition metadata blobs. (boot.bin, bi2.bin, apploader.bin, main.dol, etc.)
///
/// All pointers are borrowed and valid while the source partition handle remains alive.
#[repr(C)]
pub struct NodPartitionMeta {
    /// Disc and boot header (boot.bin)
    pub raw_boot: NodBlob,
    /// Debug and region information (bi2.bin)
    pub raw_bi2: NodBlob,
    /// Apploader (apploader.bin)
    pub raw_apploader: NodBlob,
    /// Main binary (main.dol)
    pub raw_dol: NodBlob,
    /// File system table (fst.bin)
    pub raw_fst: NodBlob,
    /// Ticket (ticket.bin, Wii only)
    pub raw_ticket: NodBlob,
    /// TMD (tmd.bin, Wii only)
    pub raw_tmd: NodBlob,
    /// Certificate chain (cert.bin, Wii only)
    pub raw_cert_chain: NodBlob,
    /// H3 hash table (h3.bin, Wii only)
    pub raw_h3_table: NodBlob,
}

impl From<&PartitionMeta> for NodPartitionMeta {
    fn from(meta: &PartitionMeta) -> Self {
        NodPartitionMeta {
            raw_boot: NodBlob::from(meta.raw_boot.as_ref().as_slice()),
            raw_bi2: NodBlob::from(meta.raw_bi2.as_ref().as_slice()),
            raw_apploader: NodBlob::from(meta.raw_apploader.as_ref()),
            raw_dol: NodBlob::from(meta.raw_dol.as_ref()),
            raw_fst: NodBlob::from(meta.raw_fst.as_ref()),
            raw_ticket: meta.raw_ticket.as_deref().map(NodBlob::from).unwrap_or_else(NodBlob::null),
            raw_tmd: meta.raw_tmd.as_deref().map(NodBlob::from).unwrap_or_else(NodBlob::null),
            raw_cert_chain: meta
                .raw_cert_chain
                .as_deref()
                .map(NodBlob::from)
                .unwrap_or_else(NodBlob::null),
            raw_h3_table: meta
                .raw_h3_table
                .as_deref()
                .map(|v| NodBlob::from(v.as_slice()))
                .unwrap_or_else(NodBlob::null),
        }
    }
}

/// Sentinel value: `nod_partition_find_file` returns this when a file is not found.
/// `nod_partition_iterate_fst` callback returns this to stop iteration.
pub const NOD_FST_STOP: u32 = u32::MAX;

/// Callback for iterating file system entries.
///
/// Parameters:
/// - `index`: node index in the FST
/// - `kind`: whether the node is a file or directory
/// - `name`: null-terminated file/directory name
/// - `size`: file size in bytes (0 for directories)
/// - `user_data`: opaque pointer passed to `nod_partition_iterate_fst`
///
/// Returns: the next node index to visit, or `NOD_FST_STOP` to stop.
pub type NodFstCallback =
    unsafe extern "C" fn(u32, NodNodeKind, *const c_char, u32, *mut c_void) -> u32;
