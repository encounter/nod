#![warn(missing_docs, clippy::missing_inline_in_public_items)]
//! Library for traversing & reading Nintendo Optical Disc (GameCube and Wii) images.
//!
//! Originally based on the C++ library [nod](https://github.com/AxioDL/nod),
//! but does not currently support authoring.
//!
//! Currently supported file formats:
//! - ISO (GCM)
//! - WIA / RVZ
//! - WBFS (+ NKit 2 lossless)
//! - CISO (+ NKit 2 lossless)
//! - NFS (Wii U VC)
//! - GCZ
//!
//! # Examples
//!
//! Opening a disc image and reading a file:
//!
//! ```no_run
//! use std::io::Read;
//!
//! // Open a disc image and the first data partition.
//! let disc = nod::Disc::new("path/to/file.iso")
//!     .expect("Failed to open disc");
//! let mut partition = disc.open_partition_kind(nod::PartitionKind::Data)
//!     .expect("Failed to open data partition");
//!
//! // Read partition metadata and the file system table.
//! let meta = partition.meta()
//!     .expect("Failed to read partition metadata");
//! let fst = meta.fst()
//!     .expect("File system table is invalid");
//!
//! // Find a file by path and read it into a string.
//! if let Some((_, node)) = fst.find("/MP3/Worlds.txt") {
//!     let mut s = String::new();
//!     partition
//!         .open_file(node)
//!         .expect("Failed to open file stream")
//!         .read_to_string(&mut s)
//!         .expect("Failed to read file");
//!     println!("{}", s);
//! }
//! ```
//!
//! Converting a disc image to raw ISO:
//!
//! ```no_run
//! // Enable `PartitionEncryptionMode::Original` to ensure the output is a valid ISO.
//! let options = nod::OpenOptions { partition_encryption: nod::PartitionEncryptionMode::Original };
//! let mut disc = nod::Disc::new_with_options("path/to/file.rvz", &options)
//!     .expect("Failed to open disc");
//!
//! // Read directly from the open disc and write to the output file.
//! let mut out = std::fs::File::create("output.iso")
//!     .expect("Failed to create output file");
//! std::io::copy(&mut disc, &mut out)
//!     .expect("Failed to write data");
//! ```

use std::{
    io::{BufRead, Read, Seek},
    path::Path,
};

pub use disc::{
    ApploaderHeader, ContentMetadata, DiscHeader, DolHeader, FileStream, Fst, Node, NodeKind,
    OwnedFileStream, PartitionBase, PartitionHeader, PartitionKind, PartitionMeta, SignedHeader,
    Ticket, TicketLimit, TmdHeader, WindowedStream, BI2_SIZE, BOOT_SIZE, DL_DVD_SIZE, GCN_MAGIC,
    MINI_DVD_SIZE, REGION_SIZE, SECTOR_SIZE, SL_DVD_SIZE, WII_MAGIC,
};
pub use io::{
    block::{DiscStream, PartitionInfo},
    Compression, DiscMeta, Format, KeyBytes, MagicBytes,
};
pub use util::lfg::LaggedFibonacci;

mod disc;
mod io;
mod util;

/// Error types for nod.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error for disc format related issues.
    #[error("disc format error: {0}")]
    DiscFormat(String),
    /// A general I/O error.
    #[error("I/O error: {0}")]
    Io(String, #[source] std::io::Error),
    /// An unknown error.
    #[error("error: {0}")]
    Other(String),
    /// An error occurred while allocating memory.
    #[error("allocation failed")]
    Alloc(zerocopy::AllocError),
}

impl From<&str> for Error {
    #[inline]
    fn from(s: &str) -> Error { Error::Other(s.to_string()) }
}

impl From<String> for Error {
    #[inline]
    fn from(s: String) -> Error { Error::Other(s) }
}

impl From<zerocopy::AllocError> for Error {
    #[inline]
    fn from(e: zerocopy::AllocError) -> Error { Error::Alloc(e) }
}

/// Helper result type for [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Helper trait for adding context to errors.
pub trait ErrorContext {
    /// Adds context to an error.
    fn context(self, context: impl Into<String>) -> Error;
}

impl ErrorContext for std::io::Error {
    #[inline]
    fn context(self, context: impl Into<String>) -> Error { Error::Io(context.into(), self) }
}

/// Helper trait for adding context to result errors.
pub trait ResultContext<T> {
    /// Adds context to a result error.
    fn context(self, context: impl Into<String>) -> Result<T>;

    /// Adds context to a result error using a closure.
    fn with_context<F>(self, f: F) -> Result<T>
    where F: FnOnce() -> String;
}

impl<T, E> ResultContext<T> for Result<T, E>
where E: ErrorContext
{
    #[inline]
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.context(context))
    }

    #[inline]
    fn with_context<F>(self, f: F) -> Result<T>
    where F: FnOnce() -> String {
        self.map_err(|e| e.context(f()))
    }
}

/// Wii partition encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PartitionEncryptionMode {
    /// Partition data is read as it's stored in the underlying disc format.
    /// For example, WIA/RVZ partitions are stored decrypted, so this avoids
    /// rebuilding the partition encryption and hash data if it will only be
    /// read via [`PartitionBase`]. If it's desired to read a full disc image
    /// via [`Disc`], use [`PartitionEncryptionMode::Original`] instead.
    #[default]
    AsIs,
    /// Partition encryption and hashes are rebuilt to match its original state,
    /// if necessary. This is used for converting or verifying a disc image.
    Original,
    /// Partition data will be encrypted if reading a decrypted disc image.
    /// Modifies the disc header to mark partition data as encrypted.
    ForceEncrypted,
    /// Partition data will be decrypted if reading an encrypted disc image.
    /// Modifies the disc header to mark partition data as decrypted.
    ForceDecrypted,
}

/// Options for opening a disc image.
#[derive(Default, Debug, Clone)]
pub struct OpenOptions {
    /// Wii: Partition encryption mode. By default, partitions are read as they
    /// are stored in the underlying disc format, avoiding extra work when the
    /// underlying format stores them decrypted (e.g. WIA/RVZ).
    ///
    /// This can be changed to [`PartitionEncryptionMode::Original`] to rebuild
    /// partition encryption and hashes to match its original state for conversion
    /// or verification.
    pub partition_encryption: PartitionEncryptionMode,
}

/// Options for opening a partition.
#[derive(Default, Debug, Clone)]
pub struct PartitionOptions {
    /// Wii: Validate data hashes while reading the partition, if available.
    /// To ensure hashes are present, regardless of the underlying disc format,
    /// set [`OpenOptions::partition_encryption`] to [`PartitionEncryptionMode::Original`].
    pub validate_hashes: bool,
}

/// An open disc image and read stream.
///
/// This is the primary entry point for reading disc images.
pub struct Disc {
    reader: disc::reader::DiscReader,
}

impl Disc {
    /// Opens a disc image from a file path.
    #[inline]
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Disc> {
        Disc::new_with_options(path, &OpenOptions::default())
    }

    /// Opens a disc image from a file path with custom options.
    #[inline]
    pub fn new_with_options<P: AsRef<Path>>(path: P, options: &OpenOptions) -> Result<Disc> {
        let io = io::block::open(path.as_ref())?;
        let reader = disc::reader::DiscReader::new(io, options)?;
        Ok(Disc { reader })
    }

    /// Opens a disc image from a read stream.
    #[inline]
    pub fn new_stream(stream: Box<dyn DiscStream>) -> Result<Disc> {
        Disc::new_stream_with_options(stream, &OpenOptions::default())
    }

    /// Opens a disc image from a read stream with custom options.
    #[inline]
    pub fn new_stream_with_options(
        stream: Box<dyn DiscStream>,
        options: &OpenOptions,
    ) -> Result<Disc> {
        let io = io::block::new(stream)?;
        let reader = disc::reader::DiscReader::new(io, options)?;
        Ok(Disc { reader })
    }

    /// Detects the format of a disc image from a read stream.
    #[inline]
    pub fn detect<R>(stream: &mut R) -> std::io::Result<Option<Format>>
    where R: Read + ?Sized {
        io::block::detect(stream)
    }

    /// The disc's primary header.
    #[inline]
    pub fn header(&self) -> &DiscHeader { self.reader.header() }

    /// The Wii disc's region information.
    ///
    /// **GameCube**: This will return `None`.
    #[inline]
    pub fn region(&self) -> Option<&[u8; REGION_SIZE]> { self.reader.region() }

    /// Returns extra metadata included in the disc file format, if any.
    #[inline]
    pub fn meta(&self) -> DiscMeta { self.reader.meta() }

    /// The disc's size in bytes, or an estimate if not stored by the format.
    #[inline]
    pub fn disc_size(&self) -> u64 { self.reader.disc_size() }

    /// A list of Wii partitions on the disc.
    ///
    /// **GameCube**: This will return an empty slice.
    #[inline]
    pub fn partitions(&self) -> &[PartitionInfo] { self.reader.partitions() }

    /// Opens a decrypted partition read stream for the specified partition index.
    ///
    /// **GameCube**: `index` must always be 0.
    #[inline]
    pub fn open_partition(&self, index: usize) -> Result<Box<dyn PartitionBase>> {
        self.open_partition_with_options(index, &PartitionOptions::default())
    }

    /// Opens a decrypted partition read stream for the specified partition index
    /// with custom options.
    ///
    /// **GameCube**: `index` must always be 0.
    #[inline]
    pub fn open_partition_with_options(
        &self,
        index: usize,
        options: &PartitionOptions,
    ) -> Result<Box<dyn PartitionBase>> {
        self.reader.open_partition(index, options)
    }

    /// Opens a decrypted partition read stream for the first partition matching
    /// the specified kind.
    ///
    /// **GameCube**: `kind` must always be [`PartitionKind::Data`].
    #[inline]
    pub fn open_partition_kind(&self, kind: PartitionKind) -> Result<Box<dyn PartitionBase>> {
        self.reader.open_partition_kind(kind, &PartitionOptions::default())
    }

    /// Opens a decrypted partition read stream for the first partition matching
    /// the specified kind with custom options.
    ///
    /// **GameCube**: `kind` must always be [`PartitionKind::Data`].
    #[inline]
    pub fn open_partition_kind_with_options(
        &self,
        kind: PartitionKind,
        options: &PartitionOptions,
    ) -> Result<Box<dyn PartitionBase>> {
        self.reader.open_partition_kind(kind, options)
    }
}

impl BufRead for Disc {
    #[inline]
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> { self.reader.fill_buf() }

    #[inline]
    fn consume(&mut self, amt: usize) { self.reader.consume(amt) }
}

impl Read for Disc {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.reader.read(buf) }
}

impl Seek for Disc {
    #[inline]
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> { self.reader.seek(pos) }
}
