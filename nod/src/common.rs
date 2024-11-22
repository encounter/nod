//! Common types.

use std::{borrow::Cow, fmt, str::FromStr, sync::Arc};

use crate::{
    disc::{wii::WiiPartitionHeader, DiscHeader, PartitionHeader, SECTOR_SIZE},
    Error, Result,
};

/// SHA-1 hash bytes
pub type HashBytes = [u8; 20];

/// AES key bytes
pub type KeyBytes = [u8; 16];

/// Magic bytes
pub type MagicBytes = [u8; 4];

/// The disc file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// ISO / GCM (GameCube master disc)
    #[default]
    Iso,
    /// CISO (Compact ISO)
    Ciso,
    /// GCZ
    Gcz,
    /// NFS (Wii U VC)
    Nfs,
    /// RVZ
    Rvz,
    /// WBFS
    Wbfs,
    /// WIA
    Wia,
    /// TGC
    Tgc,
}

impl Format {
    /// Returns the default block size for the disc format, if any.
    pub fn default_block_size(self) -> u32 {
        match self {
            Format::Ciso => crate::io::ciso::DEFAULT_BLOCK_SIZE,
            #[cfg(feature = "compress-zlib")]
            Format::Gcz => crate::io::gcz::DEFAULT_BLOCK_SIZE,
            Format::Rvz => crate::io::wia::RVZ_DEFAULT_CHUNK_SIZE,
            Format::Wbfs => crate::io::wbfs::DEFAULT_BLOCK_SIZE,
            Format::Wia => crate::io::wia::WIA_DEFAULT_CHUNK_SIZE,
            _ => 0,
        }
    }

    /// Returns the default compression algorithm for the disc format.
    pub fn default_compression(self) -> Compression {
        match self {
            #[cfg(feature = "compress-zlib")]
            Format::Gcz => crate::io::gcz::DEFAULT_COMPRESSION,
            Format::Rvz => crate::io::wia::RVZ_DEFAULT_COMPRESSION,
            Format::Wia => crate::io::wia::WIA_DEFAULT_COMPRESSION,
            _ => Compression::None,
        }
    }
}

impl fmt::Display for Format {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Iso => write!(f, "ISO"),
            Format::Ciso => write!(f, "CISO"),
            Format::Gcz => write!(f, "GCZ"),
            Format::Nfs => write!(f, "NFS"),
            Format::Rvz => write!(f, "RVZ"),
            Format::Wbfs => write!(f, "WBFS"),
            Format::Wia => write!(f, "WIA"),
            Format::Tgc => write!(f, "TGC"),
        }
    }
}

/// The disc file format's compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// No compression
    #[default]
    None,
    /// BZIP2
    Bzip2(u8),
    /// Deflate (GCZ only)
    Deflate(u8),
    /// LZMA
    Lzma(u8),
    /// LZMA2
    Lzma2(u8),
    /// Zstandard
    Zstandard(i8),
}

impl Compression {
    /// Validates the compression level. Sets the default level if the level is 0.
    pub fn validate_level(&mut self) -> Result<()> {
        match self {
            Compression::Bzip2(level) => {
                if *level == 0 {
                    *level = 9;
                }
                if *level > 9 {
                    return Err(Error::Other(format!(
                        "Invalid BZIP2 compression level: {level} (expected 1-9)"
                    )));
                }
            }
            Compression::Deflate(level) => {
                if *level == 0 {
                    *level = 9;
                }
                if *level > 10 {
                    return Err(Error::Other(format!(
                        "Invalid Deflate compression level: {level} (expected 1-10)"
                    )));
                }
            }
            Compression::Lzma(level) => {
                if *level == 0 {
                    *level = 6;
                }
                if *level > 9 {
                    return Err(Error::Other(format!(
                        "Invalid LZMA compression level: {level} (expected 1-9)"
                    )));
                }
            }
            Compression::Lzma2(level) => {
                if *level == 0 {
                    *level = 6;
                }
                if *level > 9 {
                    return Err(Error::Other(format!(
                        "Invalid LZMA2 compression level: {level} (expected 1-9)"
                    )));
                }
            }
            Compression::Zstandard(level) => {
                if *level == 0 {
                    *level = 19;
                }
                if *level < -22 || *level > 22 {
                    return Err(Error::Other(format!(
                        "Invalid Zstandard compression level: {level} (expected -22 to 22)"
                    )));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl fmt::Display for Compression {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Compression::None => write!(f, "None"),
            Compression::Bzip2(level) => {
                if *level == 0 {
                    write!(f, "BZIP2")
                } else {
                    write!(f, "BZIP2 ({level})")
                }
            }
            Compression::Deflate(level) => {
                if *level == 0 {
                    write!(f, "Deflate")
                } else {
                    write!(f, "Deflate ({level})")
                }
            }
            Compression::Lzma(level) => {
                if *level == 0 {
                    write!(f, "LZMA")
                } else {
                    write!(f, "LZMA ({level})")
                }
            }
            Compression::Lzma2(level) => {
                if *level == 0 {
                    write!(f, "LZMA2")
                } else {
                    write!(f, "LZMA2 ({level})")
                }
            }
            Compression::Zstandard(level) => {
                if *level == 0 {
                    write!(f, "Zstandard")
                } else {
                    write!(f, "Zstandard ({level})")
                }
            }
        }
    }
}

impl FromStr for Compression {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (format, level) =
            if let Some((format, level_str)) = s.split_once(':').or_else(|| s.split_once('.')) {
                let level = level_str
                    .parse::<i32>()
                    .map_err(|_| format!("Failed to parse compression level: {level_str:?}"))?;
                (format, level)
            } else {
                (s, 0)
            };
        match format.to_ascii_lowercase().as_str() {
            "" | "none" => Ok(Compression::None),
            "bz2" | "bzip2" => Ok(Compression::Bzip2(level as u8)),
            "deflate" | "gz" | "gzip" => Ok(Compression::Deflate(level as u8)),
            "lzma" => Ok(Compression::Lzma(level as u8)),
            "lzma2" | "xz" => Ok(Compression::Lzma2(level as u8)),
            "zst" | "zstd" | "zstandard" => Ok(Compression::Zstandard(level as i8)),
            _ => Err(format!("Unknown compression type: {format:?}")),
        }
    }
}

/// The kind of disc partition.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PartitionKind {
    /// Data partition.
    Data,
    /// Update partition.
    Update,
    /// Channel partition.
    Channel,
    /// Other partition kind.
    Other(u32),
}

impl fmt::Display for PartitionKind {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data => write!(f, "Data"),
            Self::Update => write!(f, "Update"),
            Self::Channel => write!(f, "Channel"),
            Self::Other(v) => {
                let bytes = v.to_be_bytes();
                write!(f, "Other ({:08X}, {})", v, String::from_utf8_lossy(&bytes))
            }
        }
    }
}

impl PartitionKind {
    /// Returns the directory name for the partition kind.
    #[inline]
    pub fn dir_name(&self) -> Cow<str> {
        match self {
            Self::Data => Cow::Borrowed("DATA"),
            Self::Update => Cow::Borrowed("UPDATE"),
            Self::Channel => Cow::Borrowed("CHANNEL"),
            Self::Other(v) => {
                let bytes = v.to_be_bytes();
                Cow::Owned(format!("P-{}", String::from_utf8_lossy(&bytes)))
            }
        }
    }
}

impl From<u32> for PartitionKind {
    #[inline]
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Data,
            1 => Self::Update,
            2 => Self::Channel,
            v => Self::Other(v),
        }
    }
}

/// Wii partition information.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// The partition index.
    pub index: usize,
    /// The kind of disc partition.
    pub kind: PartitionKind,
    /// The start sector of the partition.
    pub start_sector: u32,
    /// The start sector of the partition's (usually encrypted) data.
    pub data_start_sector: u32,
    /// The end sector of the partition's (usually encrypted) data.
    pub data_end_sector: u32,
    /// The AES key for the partition, also known as the "title key".
    pub key: KeyBytes,
    /// The Wii partition header.
    pub header: Arc<WiiPartitionHeader>,
    /// The disc header within the partition.
    pub disc_header: Arc<DiscHeader>,
    /// The partition header within the partition.
    pub partition_header: Arc<PartitionHeader>,
    /// Whether the partition data is encrypted
    pub has_encryption: bool,
    /// Whether the partition data hashes are present
    pub has_hashes: bool,
}

impl PartitionInfo {
    /// Returns the size of the partition's data region in bytes.
    #[inline]
    pub fn data_size(&self) -> u64 {
        (self.data_end_sector as u64 - self.data_start_sector as u64) * SECTOR_SIZE as u64
    }

    /// Returns whether the given sector is within the partition's data region.
    #[inline]
    pub fn data_contains_sector(&self, sector: u32) -> bool {
        sector >= self.data_start_sector && sector < self.data_end_sector
    }
}
