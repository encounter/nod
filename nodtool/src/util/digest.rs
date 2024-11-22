use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestResult {
    Crc32(u32),
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Xxh64(u64),
}

impl DigestResult {
    pub fn name(&self) -> &'static str {
        match self {
            DigestResult::Crc32(_) => "CRC32",
            DigestResult::Md5(_) => "MD5",
            DigestResult::Sha1(_) => "SHA-1",
            DigestResult::Xxh64(_) => "XXH64",
        }
    }
}

impl fmt::Display for DigestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestResult::Crc32(crc) => write!(f, "{:08x}", crc),
            DigestResult::Md5(md5) => write!(f, "{}", hex::encode(md5)),
            DigestResult::Sha1(sha1) => write!(f, "{}", hex::encode(sha1)),
            DigestResult::Xxh64(xxh64) => write!(f, "{:016x}", xxh64),
        }
    }
}
