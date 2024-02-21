//! Disc file format related logic (CISO, NFS, WBFS, WIA, etc.)

use crate::{streams::ReadStream, Result};

pub(crate) mod block;
pub(crate) mod ciso;
pub(crate) mod iso;
pub(crate) mod nfs;
pub(crate) mod nkit;
pub(crate) mod split;
pub(crate) mod wbfs;
pub(crate) mod wia;

/// SHA-1 hash bytes
pub(crate) type HashBytes = [u8; 20];

/// AES key bytes
pub(crate) type KeyBytes = [u8; 16];

/// Magic bytes
pub(crate) type MagicBytes = [u8; 4];

/// Abstraction over supported disc file formats.
pub trait DiscIO: Send + Sync {
    /// Opens a new read stream for the disc file(s).
    /// Generally does _not_ need to be used directly.
    fn open(&self) -> Result<Box<dyn ReadStream + '_>>;

    /// Returns extra metadata included in the disc file format, if any.
    fn meta(&self) -> Result<DiscMeta> { Ok(DiscMeta::default()) }

    /// If None, the file format does not store the original disc size. (e.g. WBFS, NFS)
    fn disc_size(&self) -> Option<u64>;
}

/// Extra metadata about the underlying disc file format.
#[derive(Debug, Clone, Default)]
pub struct DiscMeta {
    /// Whether Wii partitions are stored decrypted in the format.
    pub decrypted: bool,
    /// Whether the format omits Wii partition data hashes.
    pub needs_hash_recovery: bool,
    /// Whether the format supports recovering the original disc data losslessly.
    pub lossless: bool,
    /// The original disc's size in bytes, if stored by the format.
    pub disc_size: Option<u64>,
    /// The original disc's CRC32 hash, if stored by the format.
    pub crc32: Option<u32>,
    /// The original disc's MD5 hash, if stored by the format.
    pub md5: Option<[u8; 16]>,
    /// The original disc's SHA-1 hash, if stored by the format.
    pub sha1: Option<[u8; 20]>,
    /// The original disc's XXH64 hash, if stored by the format.
    pub xxhash64: Option<u64>,
}

/// Encrypts data in-place using AES-128-CBC with the given key and IV.
pub(crate) fn aes_encrypt(key: &KeyBytes, iv: KeyBytes, data: &mut [u8]) {
    use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
    <cbc::Encryptor<aes::Aes128>>::new(key.into(), &aes::Block::from(iv))
        .encrypt_padded_mut::<NoPadding>(data, data.len())
        .unwrap(); // Safe: using NoPadding
}

/// Decrypts data in-place using AES-128-CBC with the given key and IV.
pub(crate) fn aes_decrypt(key: &KeyBytes, iv: KeyBytes, data: &mut [u8]) {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    <cbc::Decryptor<aes::Aes128>>::new(key.into(), &aes::Block::from(iv))
        .decrypt_padded_mut::<NoPadding>(data)
        .unwrap(); // Safe: using NoPadding
}
